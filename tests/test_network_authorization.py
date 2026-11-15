"""Actual signed guest-wire verification; synthetic issuer, no network activation."""
import secrets
import unittest
from cryptography.hazmat.primitives.asymmetric import ec
from webos_accounts import jose
from guest_service.authorization import GRANT_TYPE, PROOF_TYPE, NetworkDenied, WireAuthorization


class GuestAuthorization(unittest.TestCase):
    def setUp(self):
        self.now = 1000
        self.issuer = ec.generate_private_key(ec.SECP256R1())
        self.client = ec.generate_private_key(ec.SECP256R1())
        self.policy = {"mode": "server", "issuer": "https://webos.test",
                       "authorityKeys": [{"kid": "fixture", "jwk": jose.public_jwk(self.issuer)}]}
        self.wire = self.new_wire()

    def new_wire(self):
        return WireAuthorization(self.policy, "a" * 64, clock=lambda: self.now)

    def signed(self, challenge, *, kind="registered", grant_type=GRANT_TYPE, proof_key=None):
        subject = ("user:" if kind == "registered" else "anon:") + "12345678-1234-1234-1234-123456789abc"
        claims = {"v": 1, "iss": "https://webos.test", "aud": "https://webos.test/guest-network",
                  "sub": subject, "sid": "fixture-session", "kind": kind,
                  "cnf": {"jwk": jose.public_jwk(self.client)}, "iat": self.now, "exp": self.now + 20,
                  "jti": secrets.token_urlsafe(32), "nonce": challenge["nonce"],
                  "connection_id": challenge["connection_id"], "policy_sha256": "a" * 64,
                  "session_deadline": self.now + 60}
        grant = jose.sign(claims, self.issuer, grant_type, "fixture")
        proof = jose.sign({"v": 1, "iss": "fixture-session", "aud": claims["aud"],
                           "nonce": claims["nonce"], "grant_sha256": jose.digest(grant),
                           "connection_id": claims["connection_id"], "policy_sha256": "a" * 64,
                           "method": "CONNECT", "path": "/guest-network", "iat": self.now,
                           "exp": self.now + 20}, proof_key or self.client, PROOF_TYPE)
        return grant, proof

    def test_registered_identity_expires_and_close_is_final(self):
        principal = self.wire.accept(*self.signed(self.wire.challenge()))
        self.assertIs(self.wire.principal, principal)
        self.assertTrue(self.wire.registered)
        self.now += 21
        self.assertIsNone(self.wire.principal)
        self.wire.close()
        with self.assertRaises(NetworkDenied):
            self.wire.challenge()

    def test_anonymous_identity_never_has_registered_state(self):
        self.wire.accept(*self.signed(self.wire.challenge(), kind="anonymous"))
        self.assertEqual(self.wire.principal.kind, "anonymous")
        self.assertFalse(self.wire.registered)
        self.wire.reset()
        self.assertIsNone(self.wire.principal)

    def test_browser_purpose_grant_is_denied(self):
        signed = self.signed(self.wire.challenge(), grant_type="codi-browser-relay-identity+jwt")
        with self.assertRaises(jose.Invalid):
            self.wire.accept(*signed)
        self.assertFalse(self.wire.registered)

    def test_another_connection_cannot_use_grant(self):
        signed = self.signed(self.wire.challenge())
        other = self.new_wire()
        other.challenge()
        with self.assertRaises(NetworkDenied):
            other.accept(*signed)

    def test_consumed_challenge_cannot_be_replayed(self):
        signed = self.signed(self.wire.challenge())
        self.wire.accept(*signed)
        with self.assertRaises(NetworkDenied):
            self.wire.accept(*signed)

    def test_proof_requires_the_bound_client_key(self):
        signed = self.signed(self.wire.challenge(), proof_key=ec.generate_private_key(ec.SECP256R1()))
        with self.assertRaises(jose.Invalid):
            self.wire.accept(*signed)
        self.assertIsNone(self.wire.principal)


if __name__ == "__main__":
    unittest.main(verbosity=2)
