#!/usr/bin/env python3
"""Actual SQLite network quotas, restart/concurrency and custody failures."""
import concurrent.futures
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]/'server';sys.path.insert(0,str(ROOT))
from guest_service.usage import Allowance,Permissions,UsageLedger,initialize_permissions,initialize_usage,set_permission
from guest_service.authorization import NetworkDenied
A='user:00000000-0000-0000-0000-000000000001';B='user:00000000-0000-0000-0000-000000000002'

class UsageChecks(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='.codi-network-usage-',dir=Path.home());self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.owner=os.getuid();self.now=1000.
        for name in ['policy','anonymous','registered']:(self.root/name).mkdir(mode=0o700)
        self.policy=self.root/'policy/permissions.sqlite3';initialize_permissions(self.policy,owner_uid=self.owner)
        self.permissions=Permissions(self.policy,owner_uid=self.owner)
        for role in ['anonymous','registered']:initialize_usage(self.root/role/'usage.sqlite3',role)
        self.registered=self.ledger('registered');self.anonymous=self.ledger('anonymous')
    def ledger(self,role):return UsageLedger(self.root/role/'usage.sqlite3',role,self.permissions,clock=lambda:self.now)
    def permission(self,subject=A,enabled=True,**changes):set_permission(self.policy,subject,enabled=enabled,allowance=replace(Allowance(),**changes),owner_uid=self.owner)
    def wire(self,subject=A,ledger=None):return (ledger or self.registered).reserve(subject,self.now+30)
    def rows(self,table='usage',role='registered'):
        with sqlite3.connect(self.root/role/'usage.sqlite3') as db:
            db.row_factory=sqlite3.Row;return [dict(row) for row in db.execute('SELECT * FROM '+table)]
    def test_real_registered_account_counts_both_connections(self):
        first=self.wire();second=self.wire();self.registered.charge(first,100);self.registered.charge(second,80)
        self.assertEqual({r['subject']:r['bytes'] for r in self.rows()},{A:180,'@service':180})
    def test_new_ledger_instance_keeps_account_usage(self):
        self.permission(window_bytes=100);wire=self.wire();self.registered.charge(wire,100);self.registered.release(wire)
        restarted=self.ledger('registered');new=self.wire(ledger=restarted)
        with self.assertRaises(NetworkDenied):restarted.charge(new,1)
    def test_other_account_has_its_own_quota(self):
        self.permission(window_bytes=100);wire=self.wire();self.registered.charge(wire,100);other=self.wire(B);self.registered.charge(other,100)
        self.assertEqual({r['subject']:r['bytes'] for r in self.rows()},{A:100,B:100,'@service':200})
    def test_anonymous_has_only_aggregate_rows(self):
        wire=self.wire('@anonymous',self.anonymous);self.anonymous.charge(wire,150)
        self.assertEqual({r['subject'] for r in self.rows(role='anonymous')},{'@anonymous','@service'})
        self.assertEqual(sorted(p.name for p in (self.root/'anonymous').iterdir()),['usage.sqlite3'])
    def test_anonymous_cannot_claim_registered_subject(self):
        with self.assertRaises(NetworkDenied):self.wire(A,self.anonymous)
        with self.assertRaises(NetworkDenied):self.wire('@anonymous',self.registered)
    def test_session_and_claimed_username_not_account_ids(self):
        for subject in ['alice','root','session-id','anon:00000000-0000-0000-0000-000000000001',A.upper(),'user:../alice']:
            with self.subTest(subject=subject),self.assertRaises(NetworkDenied):self.wire(subject)
    def test_account_specific_disable_before_admission(self):
        self.permission(enabled=False)
        with self.assertRaises(NetworkDenied):self.wire()
        self.wire(B)
    def test_disable_rechecked_on_charge_and_renewal(self):
        wire=self.wire();self.permission(enabled=False)
        with self.assertRaises(NetworkDenied):self.registered.charge(wire,1)
        with self.assertRaises(NetworkDenied):self.registered.renew(wire,self.now+30)
    def test_speed_budget_shared_by_account_wires(self):
        self.permission(bytes_per_second=100);first=self.wire();second=self.wire();self.registered.charge(first,60)
        with self.assertRaises(NetworkDenied):self.registered.charge(second,60)
        self.now+=.5;self.registered.charge(second,60)
    def test_packet_rate_budget_shared_by_account_wires(self):
        self.permission(packets_per_second=1);first=self.wire();second=self.wire();self.registered.charge(first,1)
        with self.assertRaises(NetworkDenied):self.registered.charge(second,1)
        self.now+=1;self.registered.charge(second,1)
    def test_failed_charge_does_not_consume_service_or_account_bytes(self):
        self.permission(window_bytes=100);wire=self.wire();self.registered.charge(wire,90)
        with self.assertRaises(NetworkDenied):self.registered.charge(wire,11)
        self.assertEqual({r['subject']:r['bytes'] for r in self.rows()},{A:90,'@service':90})
    def test_quota_updates_are_atomic_under_real_concurrent_sqlite_connections(self):
        self.permission(window_bytes=1000);wire=self.wire()
        def charge(_):
            try:self.registered.charge(wire,100);return True
            except NetworkDenied:return False
        with concurrent.futures.ThreadPoolExecutor(12) as pool:accepted=list(pool.map(charge,range(12)))
        self.assertEqual(sum(accepted),10);self.assertEqual({r['bytes'] for r in self.rows()},{1000})
    def test_concurrent_account_admission_is_serialized(self):
        self.permission(concurrent=2)
        def start(_):
            try:return self.wire()
            except NetworkDenied:return None
        with concurrent.futures.ThreadPoolExecutor(8) as pool:accepted=list(pool.map(start,range(8)))
        self.assertEqual(sum(v is not None for v in accepted),2)
    def test_release_frees_slot_without_erasing_usage_or_start_limits(self):
        self.permission(concurrent=1,starts_per_minute=1);wire=self.wire();self.registered.charge(wire,12);self.registered.release(wire)
        self.assertFalse(self.rows('wires'))
        with self.assertRaises(NetworkDenied):self.wire()
        self.now+=61;self.wire();self.assertEqual({r['bytes'] for r in self.rows()},{12})
    def test_crashed_wire_reservation_expires_without_resetting_counter(self):
        self.permission(concurrent=1);wire=self.wire();self.registered.charge(wire,7)
        with self.assertRaises(NetworkDenied):self.wire()
        self.now+=31;new=self.wire();self.assertNotEqual(new,wire);self.assertEqual({r['bytes'] for r in self.rows()},{7})
    def test_expired_wire_cannot_charge_or_refresh(self):
        wire=self.wire();self.now+=30
        with self.assertRaises(NetworkDenied):self.registered.charge(wire,1)
        with self.assertRaises(NetworkDenied):self.registered.renew(wire,self.now+30)
    def test_refresh_does_not_erase_usage_or_count_another_start(self):
        wire=self.wire();self.registered.charge(wire,22);self.now+=15;self.registered.renew(wire,self.now+30)
        self.assertEqual(len(self.rows('starts')),1);self.assertEqual({r['bytes'] for r in self.rows()},{22})
    def test_window_rollover_resets_allowance_but_clock_rollback_does_not(self):
        self.permission(window_bytes=100)
        with sqlite3.connect(self.policy) as db:db.execute('UPDATE settings SET window_seconds=60')
        wire=self.wire();self.registered.charge(wire,100);self.now=1060;new=self.wire();self.registered.charge(new,100)
        self.now=1000
        with self.assertRaises(NetworkDenied):self.registered.charge(new,1)
        self.assertEqual({r['window'] for r in self.rows()},{17})
    def test_service_cap_is_shared_across_registered_accounts(self):
        with sqlite3.connect(self.policy) as db:db.execute('UPDATE settings SET service_bytes=100 WHERE role="registered"')
        self.registered.charge(self.wire(A),60)
        with self.assertRaises(NetworkDenied):self.registered.charge(self.wire(B),50)
    def test_pre_auth_bytes_count_only_against_role_cap(self):
        self.registered.charge_unattributed(200);self.assertEqual([(r['subject'],r['bytes']) for r in self.rows()],[('@service',200)])
    def test_ledger_role_cannot_be_changed_by_reopening_it(self):
        with self.assertRaises(NetworkDenied):UsageLedger(self.root/'registered/usage.sqlite3','anonymous',self.permissions)
    def test_bad_or_missing_database_is_not_reinitialized(self):
        path=self.root/'registered/usage.sqlite3';path.write_bytes(b'not SQLite')
        with self.assertRaises(NetworkDenied):self.ledger('registered')
        self.assertEqual(path.read_bytes(),b'not SQLite');path.unlink()
        with self.assertRaises(NetworkDenied):self.ledger('registered')
        self.assertFalse(path.exists())
    def test_linked_or_public_ledger_refused(self):
        path=self.root/'registered/usage.sqlite3';path.chmod(0o644)
        with self.assertRaises(ValueError):self.ledger('registered')
        path.chmod(0o600);os.link(path,path.with_name('hardlink'))
        with self.assertRaises(ValueError):self.ledger('registered')
    def test_symlink_or_writable_parent_refused(self):
        path=self.root/'registered/usage.sqlite3';other=path.with_name('original');path.rename(other);path.symlink_to(other)
        with self.assertRaises(ValueError):self.ledger('registered')
        path.unlink();other.rename(path);path.parent.chmod(0o777)
        with self.assertRaises(ValueError):self.ledger('registered')
    def test_linked_journal_refused_without_touching_target(self):
        path=self.root/'registered/usage.sqlite3';target=self.root/'must-stay';target.write_bytes(b'unchanged');Path(str(path)+'-journal').symlink_to(target)
        with self.assertRaises(ValueError):self.ledger('registered')
        self.assertEqual(target.read_bytes(),b'unchanged')
    def test_policy_custody_and_schema_refused(self):
        self.policy.chmod(0o666)
        with self.assertRaises(ValueError):self.wire()
        self.policy.chmod(0o644)
        with sqlite3.connect(self.policy) as db:db.execute('UPDATE version SET value="future"')
        with self.assertRaises(ValueError):self.wire()
    def test_corrupt_policy_and_accounting_clock_fail_closed(self):
        wire=self.wire()
        with sqlite3.connect(self.root/'registered/usage.sqlite3') as db:db.execute('UPDATE meta SET high_water=-1')
        with self.assertRaises(NetworkDenied):self.registered.charge(wire,1)
        self.policy.write_bytes(b'corrupt policy')
        with self.assertRaises(NetworkDenied):self.permissions.policy('registered',A)
    def test_bounded_deadlines_sizes_and_allowances(self):
        for deadline in [self.now,self.now+32,True,float('nan')]:
            with self.subTest(deadline=deadline),self.assertRaises(ValueError):self.registered.reserve(A,deadline)
        wire=self.wire()
        for size in [0,-1,16385,True,.5]:
            with self.subTest(size=size),self.assertRaises(ValueError):self.registered.charge(wire,size)
        for changes in [{'concurrent':0},{'starts_per_minute':21},{'bytes_per_second':262145},{'window_bytes':True},{'packets_per_second':201}]:
            with self.subTest(changes=changes),self.assertRaises(ValueError):replace(Allowance(),**changes)

if __name__=='__main__':
    unittest.main(verbosity=2)
