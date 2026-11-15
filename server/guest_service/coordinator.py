"""Browser wire coordinator: private Unix workers, retained public connection.

Legacy binary clients use anonymous access. Typed text controls never enter the
NIC. Worker changes retire NAT state, not the browser VM. Root-owned socket
reservation/custody and worker peer-UID checks belong to the native operator.
"""
import asyncio
from dataclasses import dataclass
import json
from pathlib import Path
import re
import secrets
import time
from aiohttp import ClientSession,ClientTimeout,UnixConnector,WSMsgType,web,ClientError
from .authorization import NetworkDenied,context
from .worker import Budget,Limits
from webos_accounts import jose

@dataclass
class Backend:
    ws:object
    kind:str
    challenge:dict|None=None
    expires:int=0
    task:object=None

class GuestCoordinator:
    def __init__(self,origin,policy,endpoints,cookie_secret,*,base_path='',limits=None,clock=time.time):
        context(origin,base_path)
        if set(endpoints)!={'anonymous','registered'}:raise ValueError('Exactly two fixed worker endpoints required')
        for value in endpoints.values():
            if not isinstance(value,dict) or set(value)!={'socket','secret'} or not isinstance(value['socket'],str) or not re.fullmatch(r'/[A-Za-z0-9_./-]+',value['socket']) or '..' in Path(value['socket']).parts or not re.fullmatch('[A-Za-z0-9_-]{43,128}',value['secret']):raise ValueError('Fixed Unix endpoint and protected transport secret required')
        if endpoints['anonymous']['socket']==endpoints['registered']['socket']:raise ValueError('Distinct Unix workers required')
        if not isinstance(cookie_secret,str) or not re.fullmatch('[A-Za-z0-9_-]{43,128}',cookie_secret):raise ValueError('Protected browser connection cookie required')
        self.origin=origin;self.policy=policy;self.endpoints=endpoints;self.cookie=cookie_secret;self.base_path=base_path;self.limits=limits or Limits();self.clock=clock
        self.active=0;self.starts=[];self.shared_bytes=0

    async def relay(self,request):
        cookie=request.cookies.get('codi_guest_relay','')
        if request.query_string or len(request.headers.getall('Origin',[]))!=1 or request.headers.get('Origin')!=self.origin or not secrets.compare_digest(cookie.encode(),self.cookie.encode()):raise web.HTTPForbidden()
        now=time.monotonic();self.starts=[v for v in self.starts if v>now-60]
        if self.active>=4 or len(self.starts)>=20 or self.shared_bytes>=268435456:raise web.HTTPServiceUnavailable(headers={'Retry-After':'60'})
        self.starts.append(now);self.active+=1
        ws=web.WebSocketResponse(max_msg_size=16384,compress=False,heartbeat=30)
        connection=BrowserWire(self,ws)
        try:
            await ws.prepare(request);await connection.start_anonymous(notify=False);await connection.ingress()
        finally:
            await connection.close();self.active-=1
        return ws

class BrowserWire:
    def __init__(self,owner,ws):
        self.owner=owner;self.ws=ws;self.closed=False;self.controls=False;self.current=None;self.candidate=None;self.sessions={};self.budget=Budget(owner.limits);self.promotions=[]

    def charge(self,size):
        self.budget.charge(size);self.owner.shared_bytes+=size
        if self.owner.shared_bytes>268435456:raise NetworkDenied('Combined guest service traffic allowance reached')

    async def text(self,value):
        text=jose.dumps(value);self.charge(len(text.encode()));await asyncio.wait_for(self.ws.send_str(text),5)

    async def state(self,kind):
        if self.controls:await self.text({'type':'codi-guest-network-state/1','kind':kind,'policy_sha256':self.owner.policy.sha256})

    async def connect(self,kind):
        endpoint=self.owner.endpoints[kind]
        if kind not in self.sessions:
            self.sessions[kind]=ClientSession(connector=UnixConnector(path=endpoint['socket']),timeout=ClientTimeout(total=5),trust_env=False)
        ws=await self.sessions[kind].ws_connect('http://localhost/wire',headers={'Origin':self.owner.origin,'Authorization':'Codi-Wire '+endpoint['secret']},max_msg_size=16384,compress=0)
        return Backend(ws,kind)

    async def stop(self,backend):
        if backend is None:return
        task=backend.task
        if task is not None and task is not asyncio.current_task():task.cancel()
        try:await asyncio.wait_for(backend.ws.close(),5)
        except (OSError,TimeoutError):pass
        if task is not None and task is not asyncio.current_task():await asyncio.gather(task,return_exceptions=True)

    async def start_anonymous(self,*,notify=True):
        if self.closed:return
        old,candidate=self.current,self.candidate;self.current=self.candidate=None
        await self.stop(candidate);await self.stop(old)
        if self.closed:return
        backend=await self.connect('anonymous')
        if self.closed:await self.stop(backend);return
        self.current=backend;backend.task=asyncio.create_task(self.pump(backend))
        if notify:await self.state('anonymous')

    def challenge(self,value):
        if not isinstance(value,dict) or set(value)!={'type','nonce','connection_id','policy_sha256','expires_at'} or value['type']!='codi-guest-network-challenge/1' or value['policy_sha256']!=self.owner.policy.sha256:
            raise NetworkDenied('Unexpected worker authorization challenge')
        if any(not isinstance(value[k],str) or not re.fullmatch('[A-Za-z0-9_-]{43}',value[k]) for k in ['nonce','connection_id']) or type(value['expires_at']) is not int or not self.owner.clock()<value['expires_at']<=self.owner.clock()+31:
            raise NetworkDenied('Expired or invalid worker challenge')
        return value

    def ready(self,value,backend):
        if not isinstance(value,dict) or set(value)!={'type','kind','expires_at','connection_id','policy_sha256'} or value['type']!='codi-guest-network-ready/1' or value['kind']!='registered' or value['policy_sha256']!=self.owner.policy.sha256 or not backend.challenge or value['connection_id']!=backend.challenge['connection_id']:
            raise NetworkDenied('Unexpected registered worker acknowledgement')
        if type(value['expires_at']) is not int or not self.owner.clock()<value['expires_at']<=self.owner.clock()+31:raise NetworkDenied('Worker lease is not fresh')
        backend.expires=value['expires_at']

    async def begin(self):
        self.controls=True
        if self.current is not None and self.current.kind=='registered' and self.current.expires>self.owner.clock():
            await self.state('registered');return
        now=time.monotonic();self.promotions=[v for v in self.promotions if v>now-60]
        if len(self.promotions)>=8:raise NetworkDenied('Guest authorization attempt capacity reached')
        self.promotions.append(now)
        if self.current is not None and self.current.kind=='registered':await self.start_anonymous()
        candidate=self.candidate;self.candidate=None;await self.stop(candidate)
        candidate=await self.connect('registered');self.candidate=candidate
        message=await asyncio.wait_for(candidate.ws.receive(),5)
        if message.type!=WSMsgType.TEXT:raise NetworkDenied('Registered worker challenge unavailable')
        candidate.challenge=self.challenge(jose.loads(message.data));await self.text(candidate.challenge)

    async def authenticate(self,value):
        if not self.controls:raise NetworkDenied('Explicit guest authorization required')
        if self.candidate is not None:
            candidate=self.candidate
            await candidate.ws.send_str(jose.dumps(value));message=await asyncio.wait_for(candidate.ws.receive(),5)
            if message.type!=WSMsgType.TEXT:raise NetworkDenied('Worker rejected guest authorization')
            reply=jose.loads(message.data);self.ready(reply,candidate)
            self.candidate=None;old=self.current;self.current=candidate
            await self.stop(old)
            candidate.task=asyncio.create_task(self.pump(candidate));await self.text(reply)
        elif self.current is not None and self.current.kind=='registered':await self.current.ws.send_str(jose.dumps(value))
        else:raise NetworkDenied('No pending guest wire authorization')

    async def pump(self,backend):
        try:
            async for message in backend.ws:
                if self.closed or self.current is not backend:break
                if message.type==WSMsgType.BINARY:
                    if not 14<=len(message.data)<=1518:raise NetworkDenied('Invalid worker Ethernet frame')
                    if backend.kind=='registered' and backend.expires<=self.owner.clock():raise NetworkDenied('Registered reply lease expired')
                    self.charge(len(message.data));await asyncio.wait_for(self.ws.send_bytes(message.data),5)
                elif message.type==WSMsgType.TEXT and backend.kind=='registered':
                    value=jose.loads(message.data)
                    if not isinstance(value,dict):raise NetworkDenied('Object worker control required')
                    if value.get('type')=='codi-guest-network-challenge/1':backend.challenge=self.challenge(value)
                    else:self.ready(value,backend)
                    await self.text(value)
                else:raise NetworkDenied('Unexpected worker message')
        except (OSError,ValueError,TimeoutError,ClientError):pass
        finally:
            if not self.closed and self.current is backend:
                if backend.kind=='registered':
                    try:await self.start_anonymous()
                    except (OSError,ValueError,TimeoutError,ClientError):await self.ws.close(code=1013)
                else:await self.ws.close(code=1013)

    async def ingress(self):
        try:
            async for message in self.ws:
                if message.type==WSMsgType.BINARY:
                    self.charge(len(message.data))
                    if not 14<=len(message.data)<=1518:raise NetworkDenied('Invalid Ethernet frame')
                    if self.current is not None and self.current.kind=='registered' and self.current.expires<=self.owner.clock():await self.start_anonymous()
                    if self.current is not None:await self.current.ws.send_bytes(message.data)
                elif message.type==WSMsgType.TEXT:
                    self.charge(len(message.data.encode()));value=jose.loads(message.data)
                    if not isinstance(value,dict):raise NetworkDenied('Object network control required')
                    if value=={'type':'codi-guest-network-begin/1'}:
                        try:await self.begin()
                        except (OSError,ValueError,TimeoutError,ClientError):
                            candidate=self.candidate;self.candidate=None;await self.stop(candidate);await self.state('anonymous')
                    elif value=={'type':'codi-guest-network-reset/1'}:
                        self.controls=True
                        if self.candidate is not None or self.current is not None and self.current.kind=='registered':await self.start_anonymous()
                        else:await self.state('anonymous')
                    elif set(value)=={'type','grant','proof'} and value['type']=='codi-guest-network-auth/1':
                        try:await self.authenticate(value)
                        except (OSError,ValueError,TimeoutError,ClientError):
                            candidate=self.candidate;self.candidate=None;await self.stop(candidate)
                            if self.current is not None and self.current.kind=='registered':await self.start_anonymous()
                            else:await self.state('anonymous')
                    else:raise NetworkDenied('Unknown network control')
                elif message.type not in (WSMsgType.CLOSE,WSMsgType.CLOSED):raise NetworkDenied('Unsupported browser frame')
        finally:await self.close()

    async def close(self):
        if self.closed:return
        self.closed=True;current,candidate=self.current,self.candidate;self.current=self.candidate=None
        await self.stop(candidate);await self.stop(current)
        for session in self.sessions.values():await session.close()
        await self.ws.close()
