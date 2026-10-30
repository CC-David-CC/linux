"""Purpose-separated, live-session-backed identity for one guest wire.

Each connection owns an unpredictable challenge. Disconnect/restart destroys its
challenge and active grant, so no persisted file-gateway ledger is shared here.
Default/expired/reset identity is anonymous. Callers must retire an elevated
backend at expiry/reset, including its established sockets and buffered replies.
"""
from dataclasses import dataclass
from functools import wraps
import re
import secrets
import sys
import time
import threading
from pathlib import Path
from urllib.parse import urlsplit
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'codiserver-server-v0.3.0'))
from codiauth import jose

CHALLENGE='/api/v1/guest-network/challenge'
AUTHORIZE='/api/v1/guest-network/authorize'
GRANT_TYPE='codi-guest-network-identity+jwt'
PROOF_TYPE='codi-guest-network-use+jws'
LIFETIME=30

class NetworkDenied(ValueError):
    pass

def token(value):
    if not isinstance(value,str) or not re.fullmatch('[A-Za-z0-9_-]{43}',value) or len(jose.unb64(value))!=32:
        raise NetworkDenied('Canonical guest-network identifier required')
    return value

def policy_hash(value):
    if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}',value):
        raise NetworkDenied('Pinned guest-network policy hash required')
    return value

def context(origin,base_path=''):
    url=urlsplit(origin)
    if not url.hostname or url.username or url.password or url.path or url.query or url.fragment or origin!=url.geturl() or (url.scheme!='https' and not (url.scheme=='http' and url.hostname=='127.0.0.1')):
        raise NetworkDenied('Explicit same-origin guest-network authority required')
    if not isinstance(base_path,str) or base_path and not re.fullmatch(r'(?:/[A-Za-z0-9_-]+)+',base_path):
        raise NetworkDenied('Canonical guest-network mount required')
    path=base_path+'/guest-network'
    return origin+path,path

def window(value,now):
    if any(type(value.get(k)) is not int for k in ['iat','exp']) or not (value['iat']<=now+5 and value['exp']>now and 0<value['exp']-value['iat']<=LIFETIME):
        raise NetworkDenied('Expired or invalid guest-network identity')

@dataclass(frozen=True)
class NetworkPrincipal:
    subject:str
    sid:str
    kind:str
    key:dict
    deadline:int

def synchronized(function):
    @wraps(function)
    def call(self,*args,**kwargs):
        with self._lock:return function(self,*args,**kwargs)
    return call

class WireAuthorization:
    def __init__(self,issuer_policy,egress_sha256,*,base_path='',clock=time.time):
        if not isinstance(issuer_policy,dict) or issuer_policy.get('mode')!='server':
            raise NetworkDenied('Protected server issuer policy required')
        self.origin=issuer_policy['issuer'];self.audience,self.path=context(self.origin,base_path)
        self.policy_sha256=policy_hash(egress_sha256);self.clock=clock
        entries=issuer_policy.get('authorityKeys')
        if not isinstance(entries,list) or not 1<=len(entries)<=4:raise NetworkDenied('Explicit issuer public keys required')
        self.keys={}
        for entry in entries:
            if not isinstance(entry,dict) or set(entry)!={'kid','jwk'}:raise NetworkDenied('Exact issuer public key entry required')
            kid=entry['kid']
            if not isinstance(kid,str) or not 1<=len(kid)<=128 or kid in self.keys:raise NetworkDenied('Unique trusted issuer key IDs required')
            self.keys[kid]=jose.public_jwk(jose.load_public(entry['jwk']))
        self._lock=threading.RLock()
        self.connection_id=secrets.token_urlsafe(32)
        self.pending=None;self._principal=None;self.closed=False;self.starts=[]

    @property
    @synchronized
    def principal(self):
        if self.closed or self._principal is None or self._principal.deadline<=int(self.clock()):return None
        return self._principal

    @property
    def registered(self):
        principal=self.principal
        return principal is not None and principal.kind=='registered'

    @synchronized
    def reset(self):
        self.pending=None;self._principal=None

    @synchronized
    def close(self):
        self.reset();self.closed=True

    @synchronized
    def challenge(self,*,reset=False):
        if self.closed or type(reset) is not bool:raise NetworkDenied('Guest wire is closed or invalid')
        if reset:self.reset()
        now=int(self.clock());self.starts=[t for t in self.starts if t>now-60]
        if len(self.starts)>=8:raise NetworkDenied('Guest wire authorization capacity reached')
        self.starts.append(now)
        self.pending={'nonce':secrets.token_urlsafe(32),'expires_at':now+LIFETIME}
        return {'type':'codi-guest-network-challenge/1','connection_id':self.connection_id,
                'policy_sha256':self.policy_sha256,**self.pending}

    @synchronized
    def accept(self,grant,proof):
        if self.closed or self.pending is None:raise NetworkDenied('No live guest wire challenge')
        now=int(self.clock());pending=self.pending
        if pending['expires_at']<=now:raise NetworkDenied('Guest wire challenge expired')
        header,*_=jose.inspect(grant,GRANT_TYPE,8192)
        kid=header.get('kid')
        if not isinstance(kid,str) or not 1<=len(kid)<=128:raise NetworkDenied('Invalid guest-network issuer key ID')
        authority=self.keys.get(kid)
        if authority is None:raise NetworkDenied('Untrusted guest-network authority')
        claims=jose.verify(grant,authority,GRANT_TYPE,8192)
        fields={'v','iss','aud','sub','sid','kind','cnf','iat','exp','jti','nonce','connection_id','policy_sha256','session_deadline'}
        if set(claims)!=fields or type(claims['v']) is not int or claims['v']!=1 or claims['iss']!=self.origin or claims['aud']!=self.audience:
            raise NetworkDenied('Wrong guest-network grant context')
        window(claims,now)
        if type(claims['session_deadline']) is not int or claims['session_deadline']<claims['exp']:
            raise NetworkDenied('Guest grant exceeds the live session')
        token(claims['jti']);token(claims['nonce']);token(claims['connection_id']);policy_hash(claims['policy_sha256'])
        if claims['nonce']!=pending['nonce'] or claims['connection_id']!=self.connection_id or claims['policy_sha256']!=self.policy_sha256:
            raise NetworkDenied('Guest wire, nonce or egress policy changed')
        if not isinstance(claims['sid'],str) or not 1<=len(claims['sid'])<=80 or not isinstance(claims['sub'],str):
            raise NetworkDenied('Invalid guest identity binding')
        if claims['kind']=='registered':
            subject=claims['sub']
            try:valid=subject=='user:'+str(uuid.UUID(subject.removeprefix('user:')))
            except (ValueError,AttributeError):valid=False
            if not valid:raise NetworkDenied('Canonical registered account subject required')
        elif claims['kind']=='anonymous':
            subject=claims['sub']
            try:valid=subject=='anon:'+str(uuid.UUID(subject.removeprefix('anon:')))
            except (ValueError,AttributeError):valid=False
            if not valid:raise NetworkDenied('Canonical anonymous guest subject required')
        else:raise NetworkDenied('Invalid guest identity kind')
        if not isinstance(claims['cnf'],dict) or set(claims['cnf'])!={'jwk'}:raise NetworkDenied('Exact guest key binding required')
        public=jose.public_jwk(jose.load_public(claims['cnf']['jwk']))
        use=jose.verify(proof,public,PROOF_TYPE,8192)
        if set(use)!={'v','iss','aud','nonce','grant_sha256','connection_id','policy_sha256','method','path','iat','exp'} or type(use['v']) is not int or use['v']!=1:
            raise NetworkDenied('Invalid guest-network client proof')
        window(use,now)
        if use['iss']!=claims['sid'] or use['aud']!=self.audience or use['method']!='CONNECT' or use['path']!=self.path or use['nonce']!=pending['nonce'] or use['grant_sha256']!=jose.digest(grant) or use['connection_id']!=self.connection_id or use['policy_sha256']!=self.policy_sha256 or use['exp']>claims['exp']:
            raise NetworkDenied('Guest client proof context changed')
        principal=NetworkPrincipal(claims['sub'],claims['sid'],claims['kind'],public,claims['exp'])
        self.pending=None;self._principal=principal
        return principal
