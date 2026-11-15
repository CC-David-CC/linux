#!/usr/bin/env python3
"""Registered-only packet policy, frozen v1 compatibility and real nft parsing.

Kernel parsing occurs only in a fresh private network namespace; no host rules
are installed. Real UID/guest traffic and managed rollout remain later gates.
"""
import hashlib,json,subprocess,sys,unittest,socket,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]/'server';sys.path.insert(0,str(ROOT))
from guest_service.egress import EgressPolicy
from guest_service.signin_policy import SigninPolicy,parse_policy,VERSION
from guest_service.frames import permitted

OWN=('104.180.210.33',);DNS=('1.1.1.1','9.9.9.9')
ROLES={'anonymous_uid':60001,'registered_uid':60002,'frontend_uid':60003}

class PolicyTests(unittest.TestCase):
    def setUp(self):self.old=EgressPolicy(OWN,DNS);self.new=SigninPolicy(OWN,DNS)
    def test_frozen_v1_policy_and_hash(self):
        self.assertEqual(self.old.sha256,'aa1aa08dc3a8f45c3d30c6d5565a87f82495624f7353077c8a81827c21663e67')
        value=parse_policy(self.old.value());self.assertIs(type(value),EgressPolicy);self.assertEqual(value.sha256,self.old.sha256)
    def test_exact_v2_and_new_context(self):
        value=self.new.value();self.assertEqual(value['version'],VERSION);self.assertEqual(value['anonymousInternet'],'deny')
        parsed=parse_policy(value);self.assertIs(type(parsed),SigninPolicy);self.assertEqual(parsed.sha256,self.new.sha256);self.assertNotEqual(parsed.sha256,self.old.sha256)
    def test_reject_unknown_relaxed_or_extra_policy(self):
        for patch in [{'version':'unknown'},{'anonymousInternet':'allow'},{'anonymousInternet':True},{'anonymousInternet':False},{'enabled':True}]:
            with self.subTest(patch=patch),self.assertRaises(ValueError):parse_policy({**self.new.value(),**patch})
        for value in [None,{},self.new.value()|{'dnsIPv4':'1.1.1.1'}]:
            with self.assertRaises(ValueError):parse_policy(value)
    def test_all_anonymous_internet_is_denied(self):
        for address in [*OWN,*DNS,'8.8.8.8','10.0.7.84','127.0.0.1','::1','2606:4700:4700::1111']:
            for protocol,port,proxy in [('icmp-echo',None,False),('tcp',80,False),('tcp',443,False),('udp',53,True),('tcp',53,True)]:
                with self.subTest(address=address,protocol=protocol,port=port):self.assertFalse(self.new.permits(address,protocol,port,dns_proxy=proxy))
    def test_registered_behavior_is_preserved(self):
        for address in [*OWN,*DNS,'8.8.8.8','10.0.7.84','127.0.0.1','224.0.0.1','::1','192.0.2.1']:
            for protocol in ['tcp','udp','icmp-echo','other']:
                for port in [None,22,53,80,443,444]:
                    for proxy in [False,True]:
                        self.assertEqual(self.old.permits(address,protocol,port,registered=True,dns_proxy=proxy),self.new.permits(address,protocol,port,registered=True,dns_proxy=proxy))
    def test_registered_public_services_and_private_denial(self):
        self.assertTrue(self.new.permits(OWN[0],'icmp-echo',registered=True));self.assertTrue(self.new.permits(OWN[0],'tcp',443,registered=True))
        self.assertTrue(self.new.permits(DNS[0],'udp',53,registered=True,dns_proxy=True))
        self.assertFalse(self.new.permits('10.0.7.84','tcp',80,registered=True));self.assertFalse(self.new.permits('8.8.8.8','udp',53,registered=True,dns_proxy=True))
    def test_roles_are_not_client_truthy_values(self):
        for role in [1,0,'registered',None]:
            with self.assertRaises(ValueError):self.new.permits('8.8.8.8','tcp',443,registered=role)
        with self.assertRaises(ValueError):self.new.permits('8.8.8.8','tcp',443,dns_proxy=1)
    def test_virtual_dns_cannot_bypass_verified_role(self):
        payload=struct.pack('!HHHH',12345,53,8,0)
        header=struct.pack('!BBHHHBBH4s4s',0x45,0,28,1,0,64,17,0,socket.inet_aton('10.86.0.2'),socket.inet_aton('10.86.0.3'))
        frame=bytes(12)+b'\x08\x00'+header+payload
        self.assertTrue(permitted(frame,self.old))
        self.assertFalse(permitted(frame,self.new))
        self.assertTrue(permitted(frame,self.new,registered=True))
    def test_local_arp_remains_usable_before_and_after_signin(self):
        mac=bytes.fromhex('022215000001')
        frame=bytes([255])*6+mac+b'\x08\x06'+b'\0\x01\x08\0\x06\x04\0\x01'+mac+socket.inet_aton('10.86.0.2')+bytes(6)+socket.inet_aton('10.86.0.1')
        for role in [False,True]:self.assertTrue(permitted(frame,self.new,registered=role))
    def test_bad_addresses_and_dns_bypass_rejected(self):
        for own,dns in [(('10.0.0.1',),DNS),(OWN,OWN),(OWN,()),(OWN,('01.1.1.1',))]:
            with self.assertRaises(ValueError):SigninPolicy(own,dns)
    def test_registered_and_frontend_kernel_rules_unchanged(self):
        for unix in [False,True]:
            old=self.old.nftables(**ROLES,unix_workers=unix);new=self.new.nftables(**ROLES,unix_workers=unix)
            self.assertEqual(old.split(' chain registered {')[1],new.split(' chain registered {')[1])
            chain=new.split(' chain anonymous {\n')[1].split('\n }\n')[0]
            accepts=[line for line in chain.splitlines() if 'accept' in line]
            self.assertEqual(len(accepts),0 if unix else 1)
            if accepts:self.assertIn('ip daddr 127.0.0.1',accepts[0]);self.assertIn('ct direction reply',accepts[0])
            self.assertIn('counter reject with icmpx type admin-prohibited',chain)
    def test_kernel_identity_validation_preserved(self):
        for patch in [{'anonymous_uid':0},{'registered_uid':60001},{'frontend_port':8118}]:
            with self.assertRaises(ValueError):self.new.nftables(**(ROLES|patch),unix_workers=True)
    def test_generated_rules_parse_in_actual_private_kernel_namespace(self):
        for unix in [False,True]:
            rules=self.new.nftables(**ROLES,unix_workers=unix)
            child=subprocess.run(['sudo','-n','unshare','--net','--','/usr/sbin/nft','-c','-f','-'],input=rules,text=True,capture_output=True,timeout=20)
            self.assertEqual(child.returncode,0,child.stderr)

if __name__=='__main__':
    unittest.main(verbosity=2)
