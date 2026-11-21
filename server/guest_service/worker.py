"""Internal fixed-role Ethernet worker. Public clients never select an OS UID.

Registered admission and refresh require a typed live-session grant plus proof.
At expiry/reset/disconnect the whole QEMU wire is destroyed, retiring established
NAT flows and buffered replies. Native egress policy is a separate required layer.
This module alone does not install workers, routing, credentials or kernel rules.
"""
import asyncio
from dataclasses import dataclass
import re
import math
import resource
import secrets
import socket
import struct
import time
from aiohttp import web,WSMsgType
from .authorization import NetworkDenied,WireAuthorization
from .egress import OwnerEgressPolicy
from webos_accounts import jose
from .frames import permitted

@dataclass(frozen=True)
class Limits:
    session_seconds:float=1800
    bytes_per_second:int=262144
    packets_per_second:int=200
    session_bytes:int=67108864

    def __post_init__(self):
        if isinstance(self.session_seconds,bool) or not isinstance(self.session_seconds,(int,float)) or not math.isfinite(self.session_seconds) or not .05<=self.session_seconds<=1800:raise ValueError('Bounded guest session lifetime required')
        for value,maximum in [(self.bytes_per_second,262144),(self.packets_per_second,200),(self.session_bytes,67108864)]:
            if type(value) is not int or not 1<=value<=maximum:raise ValueError('Bounded guest traffic limit required')

class Budget:
    def __init__(self,limits):
        self.limits=limits;self.started=self.window=time.monotonic();self.bytes=self.packets=self.total=0
    def charge(self,size):
        now=time.monotonic()
        if now-self.started>=self.limits.session_seconds:raise NetworkDenied('Guest wire expired')
        if now-self.window>=1:self.window=now;self.bytes=self.packets=0
        self.bytes+=size;self.packets+=1;self.total+=size
        if self.bytes>self.limits.bytes_per_second or self.packets>self.limits.packets_per_second or self.total>self.limits.session_bytes:raise NetworkDenied('Guest wire traffic allowance reached')

def child_limits():
    resource.setrlimit(resource.RLIMIT_NOFILE,(256,256));resource.setrlimit(resource.RLIMIT_CORE,(0,0))

class WireWorker:
    def __init__(self,role,origin,policy,issuer_policy,secret,*,base_path='',limits=None,clock=time.time,lease_poll_seconds=1,refresh_after_seconds=15,usage=None):
        if role not in ('anonymous','registered') or not isinstance(secret,str) or not re.fullmatch('[A-Za-z0-9_-]{43,128}',secret):raise ValueError('Fixed worker role and protected transport secret required')
        if not .01<=lease_poll_seconds<=1 or not .05<=refresh_after_seconds<=15:raise ValueError('Bounded lease/refresh interval required')
        self.role=role;self.origin=origin;self.policy=policy;self.issuer_policy=issuer_policy;self.base_path=base_path;self.secret=secret;self.clock=clock
        self.lease_poll=lease_poll_seconds;self.refresh_after=refresh_after_seconds;self.limits=limits or Limits();self.active=0;self.starts=[];self.processes=set();self.forwarded=self.blocked=self.shared_bytes=0
        if usage is not None and usage.role!=role:raise ValueError('Fixed-role durable network accounting required')
        self.usage=usage
        WireAuthorization(issuer_policy,policy.sha256,base_path=base_path,clock=clock)
        if issuer_policy['issuer']!=origin:raise ValueError('Exact worker issuer origin required')

    def app(self):
        app=web.Application(client_max_size=16384);app.router.add_get('/wire',self.relay);app.router.add_get('/healthz',self.health);return app

    def authenticate(self,request):
        if request.query_string or len(request.headers.getall('Origin',[]))!=1 or request.headers.get('Origin')!=self.origin or len(request.headers.getall('Authorization',[]))!=1:
            raise web.HTTPForbidden()
        value=request.headers['Authorization'].encode('utf-8')
        if not secrets.compare_digest(value,('Codi-Wire '+self.secret).encode()):raise web.HTTPForbidden()

    async def health(self,request):
        self.authenticate(request)
        return web.json_response({'status':'ok','role':self.role,'policy_sha256':self.policy.sha256,'durable_usage':self.usage is not None},headers={'Cache-Control':'no-store'})

    async def relay(self,request):
        self.authenticate(request)
        now=time.monotonic();self.starts=[v for v in self.starts if v>now-60]
        if self.active>=4 or len(self.starts)>=20 or self.shared_bytes>=268435456:raise web.HTTPServiceUnavailable()
        self.starts.append(now);self.active+=1;parent=None;process=None;tasks=[];writer=None
        ws=web.WebSocketResponse(max_msg_size=16384,compress=False,heartbeat=30)
        close_code = 1000
        state=WireAuthorization(self.issuer_policy,self.policy.sha256,base_path=self.base_path,clock=self.clock)
        budget=Budget(self.limits);bound=None;usage_wire=None
        def scope(principal):
            if isinstance(self.policy, OwnerEgressPolicy):
                return self.policy.scope(principal.subject, int(self.clock()))
            return 'registered'
        def authorized():
            principal = state.principal
            if principal is None or principal.kind != 'registered':
                return None
            return scope(principal)
        def charge(size):
            budget.charge(size);self.shared_bytes+=size
            if self.shared_bytes>268435456:raise NetworkDenied('Worker shared traffic allowance reached')
            if self.usage is not None:
                if usage_wire is None:self.usage.charge_unattributed(size)
                else:self.usage.charge(usage_wire,size)
        def accept(message):
            nonlocal usage_wire
            if message.type!=WSMsgType.TEXT:raise NetworkDenied('Registered wire authorization required')
            charge(len(message.data.encode('utf-8')));value=jose.loads(message.data)
            if not isinstance(value,dict) or set(value)!={'type','grant','proof'} or value['type']!='codi-guest-network-auth/1':raise NetworkDenied('Exact wire authorization message required')
            principal=state.accept(value['grant'],value['proof'])
            if principal.kind != 'registered' or scope(principal) is None:
                raise NetworkDenied('Guest network is unavailable to this account')
            binding=(principal.subject,principal.sid,jose.thumbprint(principal.key))
            if bound is not None and binding!=bound:raise NetworkDenied('A worker wire cannot change account or key')
            if self.usage is not None:
                if usage_wire is None:usage_wire=self.usage.reserve(principal.subject,principal.deadline)
                else:self.usage.renew(usage_wire,principal.deadline)
            return binding
        async def send(value):
            text=jose.dumps(value);charge(len(text.encode()));await asyncio.wait_for(ws.send_str(text),5)
        async def accepted():
            principal=state.principal
            capability = authorized()
            if principal is None or capability is None:raise NetworkDenied('Registered wire grant expired')
            deadline = min(principal.deadline, self.policy.test_end) if capability == 'test' else principal.deadline
            await send({'type':'codi-guest-network-ready/1','kind':'registered','expires_at':deadline,'connection_id':state.connection_id,'policy_sha256':self.policy.sha256})
        try:
            await ws.prepare(request)
            if self.role=='registered':
                await send(state.challenge());bound=accept(await asyncio.wait_for(ws.receive(),10));await accepted()
            elif self.usage is not None:usage_wire=self.usage.reserve('@anonymous',self.usage.clock()+30)
            if self.role=='registered' and authorized() is None:raise NetworkDenied('Grant expired before backend admission')
            parent,child=socket.socketpair();parent.setblocking(False)
            command=['/usr/bin/qemu-system-i386','-machine','none','-nodefaults','-no-user-config','-display','none','-monitor','none','-serial','none','-m','16M',
                     '-netdev','user,id=wan,ipv6=off,net=10.86.0.0/24,host=10.86.0.1,dhcpstart=10.86.0.2,dns=10.86.0.3',
                     '-netdev',f'socket,id=wire,fd={child.fileno()}','-netdev','hubport,id=p0,hubid=0,netdev=wan','-netdev','hubport,id=p1,hubid=0,netdev=wire']
            try:process=await asyncio.create_subprocess_exec(*command,pass_fds=(child.fileno(),),stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL,preexec_fn=child_limits)
            finally:child.close()
            self.processes.add(process.pid)
            if self.role=='registered' and authorized() is None:raise NetworkDenied('Grant expired during backend startup')
            reader,writer=await asyncio.open_connection(sock=parent);parent=None
            async def ingress():
                async for message in ws:
                    capability = authorized()
                    if self.role=='registered' and capability is None:raise NetworkDenied('Registered wire grant expired')
                    if message.type==WSMsgType.TEXT and self.role=='registered':accept(message);await accepted();continue
                    if message.type!=WSMsgType.BINARY:raise NetworkDenied('Binary Ethernet required')
                    frame=message.data;charge(len(frame))
                    if len(frame)>1518:raise NetworkDenied('Oversized Ethernet frame')
                    if not permitted(frame,self.policy,registered=self.role=='registered',scope=capability):
                        self.blocked+=1;continue
                    writer.write(struct.pack('!I',len(frame))+frame);await asyncio.wait_for(writer.drain(),5);self.forwarded+=1
            async def egress():
                while True:
                    size=struct.unpack('!I',await reader.readexactly(4))[0]
                    if not 14<=size<=1518:raise NetworkDenied('Invalid backend Ethernet frame')
                    frame=await reader.readexactly(size)
                    if self.role=='registered' and authorized() is None:raise NetworkDenied('Registered reply grant expired')
                    charge(size);await asyncio.wait_for(ws.send_bytes(frame),5)
            async def lease():
                last=time.monotonic()
                while True:
                    await asyncio.sleep(self.lease_poll)
                    if authorized() is None:raise NetworkDenied('Registered wire grant expired')
                    if time.monotonic()-last>=self.refresh_after and state.pending is None:await send(state.challenge());last=time.monotonic()
            async def accounting_lease():
                while True:
                    await asyncio.sleep(1)
                    principal=state.principal
                    deadline=principal.deadline if self.role=='registered' and principal is not None else self.usage.clock()+30
                    if self.role=='registered' and principal is None:raise NetworkDenied('Registered accounting lease expired')
                    self.usage.renew(usage_wire,deadline)
            tasks=[asyncio.create_task(ingress()),asyncio.create_task(egress()),asyncio.create_task(process.wait()),asyncio.create_task(asyncio.sleep(self.limits.session_seconds))]
            if self.role=='registered':tasks.append(asyncio.create_task(lease()))
            if self.usage is not None:tasks.append(asyncio.create_task(accounting_lease()))
            await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
        except (ValueError,TimeoutError,ConnectionError,asyncio.IncompleteReadError):
            if ws.prepared:close_code = 1008
            else:raise
        finally:
            state.close()
            for task in tasks:task.cancel()
            if tasks:await asyncio.gather(*tasks,return_exceptions=True)
            if writer is not None:
                writer.close()
            if parent is not None:parent.close()
            if process is not None:
                if process.returncode is None:
                    process.terminate()
                    try:await asyncio.wait_for(process.wait(),3)
                    except asyncio.TimeoutError:process.kill();await process.wait()
                self.processes.discard(process.pid)
            if writer is not None:
                try:await writer.wait_closed()
                except (ConnectionError,OSError):pass
            if usage_wire is not None:
                try:self.usage.release(usage_wire)
                except (ValueError,OSError):pass # Expiring reservation survives a storage outage.
            self.active-=1
            if ws.prepared:
                reason = b'Guest wire authorization or allowance ended' if close_code == 1008 else b''
                await ws.close(code=close_code, message=reason)
        return ws
