"""Actual signed guest-wire verification; synthetic issuer, no network activation."""
import asyncio
import secrets
import os
import tempfile
from pathlib import Path
import socket
import unittest
from unittest.mock import AsyncMock, patch

from aiohttp import WSMsgType
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric import ec
from webos_accounts import jose
from guest_service.authorization import GRANT_TYPE, PROOF_TYPE, NetworkDenied, WireAuthorization
from guest_service.egress import EgressPolicy, OwnerEgressPolicy, parse_runtime_policy
from guest_service.worker import WireWorker
from guest_service.usage import Permissions, UsageLedger, initialize_permissions, initialize_usage, set_permission


def signed(issuer, client, now, challenge, *, subject, kind, grant_type=GRANT_TYPE, proof_key=None):
    claims = {"v": 1, "iss": "https://webos.test", "aud": "https://webos.test/guest-network",
              "sub": subject, "sid": "fixture-session", "kind": kind,
              "cnf": {"jwk": jose.public_jwk(client)}, "iat": now, "exp": now + 20,
              "jti": secrets.token_urlsafe(32), "nonce": challenge["nonce"],
              "connection_id": challenge["connection_id"], "policy_sha256": challenge["policy_sha256"],
              "session_deadline": now + 60}
    grant = jose.sign(claims, issuer, grant_type, "fixture")
    proof = jose.sign({"v": 1, "iss": "fixture-session", "aud": claims["aud"],
                       "nonce": claims["nonce"], "grant_sha256": jose.digest(grant),
                       "connection_id": claims["connection_id"], "policy_sha256": claims["policy_sha256"],
                       "method": "CONNECT", "path": "/guest-network", "iat": now,
                       "exp": now + 20}, proof_key or client, PROOF_TYPE)
    return grant, proof


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
        return signed(self.issuer, self.client, self.now, challenge, subject=subject, kind=kind,
                      grant_type=grant_type, proof_key=proof_key)

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


OWNER = "user:12dfe987-52a1-42ce-811a-657051322b71"
TEST = "user:9933e9c9-33a2-4570-9070-a43b4f615dcf"
UNRELATED = "user:5d120617-1e31-4bdd-b5f0-4bb77acfb1ab"
FIXTURE_SSH = "192.168.56.25"


def owner_policy():
    return OwnerEgressPolicy(("8.8.4.4",), ("1.1.1.1",), OWNER, FIXTURE_SSH, TEST, 900, 1008)


class OwnerPolicyTest(unittest.TestCase):
    def test_allow_only_the_configured_account_and_expiring_ssh_scope(self):
        policy = owner_policy()
        self.assertEqual(policy, parse_runtime_policy(policy.value()))
        legacy = EgressPolicy(policy.own_public_ipv4, policy.dns_ipv4)
        self.assertEqual(legacy, parse_runtime_policy(legacy.value()))
        self.assertNotEqual(policy.sha256, legacy.sha256)
        self.assertEqual(policy.scope(OWNER, 1009), "owner")
        self.assertEqual(policy.scope(TEST, 1000), "test")
        self.assertIsNone(policy.scope(TEST, 899))
        self.assertIsNone(policy.scope(TEST, 1008))
        self.assertIsNone(policy.scope(UNRELATED, 1000))
        self.assertIsNone(policy.scope(None, 1000))
        for subject, dest, proto, port, expected in [
            (OWNER, FIXTURE_SSH, "tcp", 22, True), (TEST, FIXTURE_SSH, "tcp", 22, True),
            (TEST, FIXTURE_SSH, "tcp", 443, False), (TEST, "192.168.56.26", "tcp", 22, False),
            (OWNER, "192.168.56.26", "tcp", 22, False), (OWNER, "1.1.1.1", "tcp", 443, True),
            (OWNER, "1.1.1.1", "tcp", 22, False), (TEST, "1.1.1.1", "tcp", 443, False),
            (UNRELATED, FIXTURE_SSH, "tcp", 22, False), (None, "1.1.1.1", "icmp-echo", None, False),
        ]:
            with self.subTest(subject=subject, destination=dest, protocol=proto, port=port):
                self.assertEqual(policy.permits(dest, proto, port, registered=bool(subject), scope=policy.scope(subject, 1000)), expected)
        self.assertTrue(policy.permits("1.1.1.1", "udp", 53, registered=True, dns_proxy=True, scope="owner"))
        self.assertFalse(policy.permits("1.1.1.1", "udp", 53, registered=True, dns_proxy=True, scope="test"))

    def test_scoped_rollout_has_no_owner_or_general_egress(self):
        policy = parse_runtime_policy({**owner_policy().value(), "ownerSubject": None})
        for other in (None, OWNER, UNRELATED):
            self.assertIsNone(policy.scope(other, 1000))
        self.assertEqual(policy.scope(TEST, 1000), "test")
        self.assertIsNone(policy.scope(TEST, 1008))
        self.assertEqual(policy.public_preview()["externalNetwork"], "scoped-test-only")
        self.assertFalse(policy.permits("1.1.1.1", "tcp", 443, registered=True, scope="owner"))
        for unix in (True, False):
            rules = policy.nftables(anonymous_uid=6101, registered_uid=6102, frontend_uid=6103, unix_workers=unix)
            registered = rules.split(" chain registered {\n", 1)[1].split("\n }", 1)[0].splitlines()
            permits = [line.strip() for line in registered if "ct direction reply" not in line]
            self.assertEqual(permits, [f"ip daddr {FIXTURE_SSH} tcp dport 22 counter accept",
                                       "counter reject with icmpx type admin-prohibited"])
            self.assertEqual(len(registered) - len(permits), int(not unix))

    def test_firewall_and_public_metadata_keep_the_same_boundary(self):
        policy = owner_policy()
        rules = policy.nftables(anonymous_uid=6101, registered_uid=6102, frontend_uid=6103, unix_workers=True)
        anonymous = rules.split(" chain anonymous {\n", 1)[1].split("\n }", 1)[0]
        self.assertEqual(anonymous, "  counter reject with icmpx type admin-prohibited")
        self.assertEqual(rules.count(f"ip daddr {FIXTURE_SSH} tcp dport 22 counter accept"), 1)
        preview = str(policy.public_preview())
        for value in (OWNER, TEST, FIXTURE_SSH):
            self.assertNotIn(value, preview)
        for invalid in ({"sshHost": "127.0.0.1"}, {"sshHost": "10.86.0.1"}, {"ownerSubject": "owner"},
                        {"test": {"subject": OWNER, "start": 900, "end": 1008}}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                parse_runtime_policy({**policy.value(), **invalid})


class OwnerWireTest(unittest.IsolatedAsyncioTestCase):
    async def test_only_signed_allowed_subjects_enter_the_worker(self):
        issuer = ec.generate_private_key(ec.SECP256R1())
        client_key = ec.generate_private_key(ec.SECP256R1())
        issuer_policy = {"mode": "server", "issuer": "https://webos.test",
                         "authorityKeys": [{"kid": "fixture", "jwk": jose.public_jwk(issuer)}]}
        for subject, kind, now, expected in [
            (OWNER, "registered", 1000, 1020),
            (TEST, "registered", 1000, 1008),
            (UNRELATED, "registered", 1000, None),
            (UNRELATED.replace("user:", "anon:"), "anonymous", 1000, None),
            (TEST, "registered", 1009, None),
        ]:
            with self.subTest(subject=subject, kind=kind, now=now):
                secret = secrets.token_urlsafe(32)
                worker = WireWorker("registered", "https://webos.test", owner_policy(), issuer_policy, secret, clock=lambda: now)
                # Exercise the real wire and verifier, stopping before QEMU or any network access.
                spawn = AsyncMock(side_effect=NetworkDenied("test ends before guest socket creation"))
                with patch("guest_service.worker.asyncio.create_subprocess_exec", spawn):
                    async with TestClient(TestServer(worker.app())) as browser:
                        async with browser.ws_connect("/wire", headers={"Origin": "https://webos.test", "Authorization": "Codi-Wire " + secret}) as wire:
                            challenge = await wire.receive_json(timeout=3)
                            grant, proof = signed(issuer, client_key, now, challenge, subject=subject, kind=kind)
                            await wire.send_json({"type": "codi-guest-network-auth/1", "grant": grant, "proof": proof})
                            if expected is None:
                                self.assertEqual((await wire.receive(timeout=3)).type, WSMsgType.CLOSE)
                                spawn.assert_not_awaited()
                            else:
                                ready = await wire.receive_json(timeout=3)
                                self.assertEqual(ready["expires_at"], expected)
                                self.assertEqual((await wire.receive(timeout=3)).type, WSMsgType.CLOSE)
                                spawn.assert_awaited_once()

    async def test_expired_test_window_retires_the_existing_worker(self):
        await self.check_existing_wire(revoke=False)

    async def test_revoked_account_retires_an_idle_worker_before_expiry(self):
        await self.check_existing_wire(revoke=True)

    async def check_existing_wire(self, *, revoke):
        issuer = ec.generate_private_key(ec.SECP256R1())
        client_key = ec.generate_private_key(ec.SECP256R1())
        issuer_policy = {"mode": "server", "issuer": "https://webos.test",
                         "authorityKeys": [{"kid": "fixture", "jwk": jose.public_jwk(issuer)}]}
        now = 1000
        secret = secrets.token_urlsafe(32)
        retired = asyncio.Event()
        started = asyncio.Event()
        usage = None
        if revoke:
            directory = Path(self.enterContext(tempfile.TemporaryDirectory(dir=Path.home())))
            permissions = directory / 'permissions.sqlite'
            uid = os.getuid()
            initialize_permissions(permissions, owner_uid=uid)
            set_permission(permissions, TEST, enabled=True, owner_uid=uid)
            ledger = directory / 'usage.sqlite'
            initialize_usage(ledger, 'registered')
            usage = UsageLedger(ledger, 'registered', Permissions(permissions, owner_uid=uid), clock=lambda: now)
        worker = WireWorker("registered", "https://webos.test", owner_policy(), issuer_policy, secret,
                            clock=lambda: now, lease_poll_seconds=.01, usage=usage)

        class TestProcess:
            pid = 1
            returncode = None

            def __init__(self, fd):
                self.socket = socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_STREAM)

            async def wait(self):
                await retired.wait()
                return self.returncode

            def terminate(self):
                self.returncode = 0
                self.socket.close()
                retired.set()

        async def local_only_process(*args, pass_fds, **kwargs):
            process = TestProcess(pass_fds[0])
            started.set()
            return process

        with patch("guest_service.worker.asyncio.create_subprocess_exec", local_only_process):
            async with TestClient(TestServer(worker.app())) as browser:
                async with browser.ws_connect("/wire", headers={"Origin": "https://webos.test", "Authorization": "Codi-Wire " + secret}) as wire:
                    challenge = await wire.receive_json(timeout=3)
                    grant, proof = signed(issuer, client_key, now, challenge, subject=TEST, kind="registered")
                    await wire.send_json({"type": "codi-guest-network-auth/1", "grant": grant, "proof": proof})
                    self.assertEqual((await wire.receive_json(timeout=3))["expires_at"], 1008)
                    await asyncio.wait_for(started.wait(), 3)
                    self.assertFalse(retired.is_set())
                    if revoke:
                        set_permission(permissions, TEST, enabled=False, owner_uid=uid)
                    else:
                        now = 1008
                    await asyncio.wait_for(retired.wait(), 3)
                    self.assertEqual((await wire.receive(timeout=3)).type, WSMsgType.CLOSE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
