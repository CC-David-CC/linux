"""Root-controlled network permissions and worker-owned durable usage.

Registered counters belong to canonical account IDs, never session IDs. The
anonymous worker has one aggregate subject and creates no anonymous user homes.
Each role owns its own ledger; neither worker can write the other's counters.
This is an application quota boundary, additional to independent kernel egress.
"""
from contextlib import contextmanager
from dataclasses import asdict,dataclass
import math
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time
import uuid

from .authorization import NetworkDenied

ROLES=('anonymous','registered')
FIELDS=('window_bytes','bytes_per_second','packets_per_second','concurrent','starts_per_minute')

def account(value):
    if not isinstance(value,str):raise NetworkDenied('Canonical registered network account required')
    try:valid=value=='user:'+str(uuid.UUID(value.removeprefix('user:')))
    except ValueError:valid=False
    if not valid:raise NetworkDenied('Canonical registered network account required')
    return value

def number(value,low,high):
    if type(value) is not int or not low<=value<=high:raise ValueError('Bounded network allowance required')
    return value

@dataclass(frozen=True)
class Allowance:
    window_bytes:int=67108864
    bytes_per_second:int=262144
    packets_per_second:int=200
    concurrent:int=4
    starts_per_minute:int=20
    def __post_init__(self):
        for key,low,high in [('window_bytes',1,268435456),('bytes_per_second',1,262144),('packets_per_second',1,200),('concurrent',1,4),('starts_per_minute',1,20)]:number(getattr(self,key),low,high)

def protected(path,owner,mode,*,directory=False):
    path=Path(path)
    if not path.is_absolute() or any(p in ('','.','..') for p in str(path).split('/')[1:]):raise ValueError('Canonical absolute network state path required')
    for parent in path.parents:
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,owner) or info.st_mode&0o022:raise ValueError('Protected network state ancestors required')
    info=path.lstat()
    if info.st_uid!=owner or stat.S_IMODE(info.st_mode)!=mode:raise ValueError('Network state custody changed')
    if directory:
        if not stat.S_ISDIR(info.st_mode):raise ValueError('Network state directory required')
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise ValueError('Regular unlinked network state file required')
    return path

def connect(path,*,readonly=False):
    # DELETE journals avoid writable WAL sidecars for the read-only policy DB.
    db=sqlite3.connect(path.as_uri()+'?mode='+('ro' if readonly else 'rw'),uri=True,timeout=1,isolation_level=None)
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA trusted_schema=OFF');db.execute('PRAGMA foreign_keys=ON');db.execute('PRAGMA busy_timeout=1000')
    if readonly:db.execute('PRAGMA query_only=ON')
    else:db.execute('PRAGMA synchronous=FULL')
    return db

def create_file(path,owner):
    path=Path(path);protected(path.parent,owner,0o700,directory=True)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    os.close(fd)
    return path

def initialize_permissions(path,*,owner_uid=0,window_seconds=86400,anonymous=None,registered=None,anonymous_service_bytes=67108864,registered_service_bytes=201326592):
    number(window_seconds,60,86400)
    for size in (anonymous_service_bytes,registered_service_bytes):number(size,1,268435456)
    path=create_file(path,owner_uid)
    db=connect(path)
    try:
        db.executescript('BEGIN IMMEDIATE; CREATE TABLE version(id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL); INSERT INTO version VALUES(1,"codi-network-permissions/1"); CREATE TABLE settings(role TEXT PRIMARY KEY, window_seconds INTEGER NOT NULL, service_bytes INTEGER NOT NULL); CREATE TABLE permissions(subject TEXT PRIMARY KEY, enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), window_bytes INTEGER NOT NULL, bytes_per_second INTEGER NOT NULL, packets_per_second INTEGER NOT NULL, concurrent INTEGER NOT NULL, starts_per_minute INTEGER NOT NULL); COMMIT;')
        db.execute('BEGIN IMMEDIATE')
        for role,allowance,cap in [('anonymous',anonymous or Allowance(),anonymous_service_bytes),('registered',registered or Allowance(),registered_service_bytes)]:
            db.execute('INSERT INTO settings VALUES(?,?,?)',(role,window_seconds,cap));db.execute('INSERT INTO permissions VALUES(?,1,?,?,?,?,?)',('@'+role,*asdict(allowance).values()))
        db.execute('COMMIT')
    finally:db.close()
    # Policy is public authorization metadata. Only its root owner may write.
    path.chmod(0o644)

def set_permission(path,subject,*,enabled,allowance=None,owner_uid=0):
    account(subject)
    if type(enabled) is not bool:raise ValueError('Explicit network permission decision required')
    protected(path,owner_uid,0o644)
    db=connect(Path(path))
    try:
        db.execute('BEGIN IMMEDIATE')
        row=db.execute('SELECT * FROM permissions WHERE subject=?',('@registered',)).fetchone()
        if row is None:raise ValueError('Missing registered network defaults')
        chosen=allowance or Allowance(**{key:row[key] for key in FIELDS})
        db.execute('INSERT INTO permissions VALUES(?,?,?,?,?,?,?) ON CONFLICT(subject) DO UPDATE SET enabled=excluded.enabled, window_bytes=excluded.window_bytes, bytes_per_second=excluded.bytes_per_second, packets_per_second=excluded.packets_per_second, concurrent=excluded.concurrent, starts_per_minute=excluded.starts_per_minute',(subject,int(enabled),*asdict(chosen).values()))
        db.execute('COMMIT')
    finally:db.close()

class Permissions:
    def __init__(self,path,*,owner_uid=0):self.path=Path(path);self.owner=owner_uid
    @contextmanager
    def read(self):
        db=None
        try:
            protected(self.path,self.owner,0o644)
            db=connect(self.path,readonly=True)
            version=db.execute('SELECT value FROM version WHERE id=1').fetchone()
            if version is None or version[0]!='codi-network-permissions/1':raise ValueError('Unsupported network permission database')
            db.execute('BEGIN');yield db
        except (sqlite3.Error,OSError,TypeError,KeyError) as error:raise NetworkDenied('Network permissions unavailable') from error
        finally:
            if db is not None:db.close()
    def defaults(self,role):
        if role not in ROLES:raise NetworkDenied('Fixed network role required')
        return self._policy(role,'@'+role)
    def policy(self,role,subject):
        if role not in ROLES or role=='anonymous' and subject!='@anonymous':raise NetworkDenied('Fixed anonymous network subject required')
        if role=='registered':account(subject)
        return self._policy(role,subject)
    def _policy(self,role,subject):
        with self.read() as db:
            row=db.execute('SELECT * FROM permissions WHERE subject=?',(subject,)).fetchone()
            if row is None:row=db.execute('SELECT * FROM permissions WHERE subject=?',('@'+role,)).fetchone()
            settings=db.execute('SELECT * FROM settings WHERE role=?',(role,)).fetchone()
            if row is None or settings is None or row['enabled']!=1:raise NetworkDenied('Network access is disabled for this account')
            allowance=Allowance(**{key:row[key] for key in FIELDS})
            return allowance,number(settings['window_seconds'],60,86400),number(settings['service_bytes'],1,268435456)

def initialize_usage(path,role,*,owner_uid=None):
    if role not in ROLES:raise ValueError('Fixed network worker role required')
    owner_uid=os.geteuid() if owner_uid is None else owner_uid
    path=create_file(path,owner_uid);db=connect(path)
    try:
        db.executescript('BEGIN IMMEDIATE; CREATE TABLE meta(id INTEGER PRIMARY KEY CHECK(id=1), version TEXT NOT NULL, role TEXT NOT NULL, high_water REAL NOT NULL); CREATE TABLE usage(subject TEXT PRIMARY KEY, window INTEGER NOT NULL, bytes INTEGER NOT NULL, packets INTEGER NOT NULL, updated REAL NOT NULL, byte_tokens REAL NOT NULL, packet_tokens REAL NOT NULL); CREATE TABLE wires(id TEXT PRIMARY KEY, subject TEXT NOT NULL, deadline REAL NOT NULL); CREATE INDEX wire_subject ON wires(subject); CREATE TABLE starts(id TEXT PRIMARY KEY, subject TEXT NOT NULL, at REAL NOT NULL); CREATE INDEX start_subject ON starts(subject,at); COMMIT;')
        db.execute('INSERT INTO meta VALUES(1,?,?,0)',('codi-network-usage/1',role))
    finally:db.close()

class UsageLedger:
    def __init__(self,path,role,permissions,*,clock=time.time,owner_uid=None):
        if role not in ROLES:raise ValueError('Fixed network worker role required')
        self.path=Path(path);self.role=role;self.permissions=permissions;self.clock=clock;self.owner=os.geteuid() if owner_uid is None else owner_uid
        # Validate existing custody/schema immediately; never silently reset it.
        with self.transaction():pass
    @contextmanager
    def transaction(self):
        db=None
        try:
            protected(self.path,self.owner,0o600)
            for suffix in ['-journal','-wal','-shm']:
                side=Path(str(self.path)+suffix)
                if side.exists() or side.is_symlink():protected(side,self.owner,0o600)
            db=connect(self.path)
            db.execute('BEGIN IMMEDIATE')
            meta=db.execute('SELECT * FROM meta WHERE id=1').fetchone()
            if meta is None or meta['version']!='codi-network-usage/1' or meta['role']!=self.role:raise NetworkDenied('Network usage role or schema changed')
            if not isinstance(meta['high_water'],(int,float)) or not math.isfinite(meta['high_water']) or meta['high_water']<0:raise NetworkDenied('Network accounting clock state changed')
            now=self.clock()
            if isinstance(now,bool) or not isinstance(now,(float,int)) or not math.isfinite(now) or now<0:raise NetworkDenied('Invalid network accounting clock')
            now=max(float(now),meta['high_water']);db.execute('UPDATE meta SET high_water=? WHERE id=1',(now,))
            db.execute('DELETE FROM wires WHERE deadline<=?',(now,));db.execute('DELETE FROM starts WHERE at<=?',(now-60,))
            yield db,now
            db.execute('COMMIT')
        except (sqlite3.Error,OSError,TypeError,KeyError) as error:
            raise NetworkDenied('Durable network accounting unavailable') from error
        finally:
            if db is not None:db.close()
    def reserve(self,subject,deadline):
        allowance,seconds,cap=self.permissions.policy(self.role,subject)
        with self.transaction() as (db,now):
            self.deadline(deadline,now)
            if db.execute('SELECT count(*) FROM wires WHERE subject=?',(subject,)).fetchone()[0]>=allowance.concurrent:raise NetworkDenied('Account network connection allowance reached')
            if db.execute('SELECT count(*) FROM starts WHERE subject=?',(subject,)).fetchone()[0]>=allowance.starts_per_minute:raise NetworkDenied('Account network start allowance reached')
            self.record(db,subject,now,allowance,seconds,cap,0)
            wire=secrets.token_urlsafe(32);db.execute('INSERT INTO wires VALUES(?,?,?)',(wire,subject,deadline));db.execute('INSERT INTO starts VALUES(?,?,?)',(wire,subject,now));return wire
    @staticmethod
    def deadline(value,now):
        if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or not now<value<=now+31:raise NetworkDenied('Bounded network reservation deadline required')
    def renew(self,wire,deadline):
        with self.transaction() as (db,now):
            self.deadline(deadline,now);row=db.execute('SELECT subject FROM wires WHERE id=?',(wire,)).fetchone()
            if row is None:raise NetworkDenied('Network reservation expired')
            self.permissions.policy(self.role,row['subject']);db.execute('UPDATE wires SET deadline=? WHERE id=?',(deadline,wire))
    def release(self,wire):
        with self.transaction() as (db,now):db.execute('DELETE FROM wires WHERE id=?',(wire,))
    def record(self,db,subject,now,allowance,seconds,cap,size):
        window=int(now)//seconds
        for key,maximum,rate in [('@service',cap,False),(subject,allowance.window_bytes,True)]:
            row=db.execute('SELECT * FROM usage WHERE subject=?',(key,)).fetchone()
            used=packets=0
            byte_tokens=float(allowance.bytes_per_second);packet_tokens=float(allowance.packets_per_second)
            if row is not None:
                if row['window']==window:used=row['bytes'];packets=row['packets']
                elapsed=max(0,now-row['updated']);byte_tokens=min(byte_tokens,row['byte_tokens']+elapsed*allowance.bytes_per_second);packet_tokens=min(packet_tokens,row['packet_tokens']+elapsed*allowance.packets_per_second)
            if used+size>maximum:raise NetworkDenied('Durable network byte allowance reached')
            if rate and size and (byte_tokens<size or packet_tokens<1):raise NetworkDenied('Account network speed allowance reached')
            if rate and size:byte_tokens-=size;packet_tokens-=1
            db.execute('INSERT INTO usage VALUES(?,?,?,?,?,?,?) ON CONFLICT(subject) DO UPDATE SET window=excluded.window,bytes=excluded.bytes,packets=excluded.packets,updated=excluded.updated,byte_tokens=excluded.byte_tokens,packet_tokens=excluded.packet_tokens',(key,window,used+size,packets+int(size>0),now,byte_tokens,packet_tokens))
    def charge(self,wire,size):
        number(size,1,16384)
        with self.transaction() as (db,now):
            row=db.execute('SELECT subject FROM wires WHERE id=?',(wire,)).fetchone()
            if row is None:raise NetworkDenied('Network reservation expired')
            allowance,seconds,cap=self.permissions.policy(self.role,row['subject'])
            self.record(db,row['subject'],now,allowance,seconds,cap,size)
    def charge_unattributed(self,size):
        # Registered handshake bytes are bounded by the existing wire Budget;
        # count them against the durable role cap before an account is proven.
        number(size,1,16384)
        allowance,seconds,cap=self.permissions.defaults(self.role)
        with self.transaction() as (db,now):
            window=int(now)//seconds;row=db.execute('SELECT * FROM usage WHERE subject="@service"').fetchone();used=row['bytes'] if row and row['window']==window else 0;packets=row['packets'] if row and row['window']==window else 0
            if used+size>cap:raise NetworkDenied('Durable network service allowance reached')
            db.execute('INSERT INTO usage VALUES("@service",?,?,?,?,0,0) ON CONFLICT(subject) DO UPDATE SET window=excluded.window,bytes=excluded.bytes,packets=excluded.packets,updated=excluded.updated',(window,used+size,packets+1,now))
