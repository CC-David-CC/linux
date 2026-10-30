#!/usr/bin/env python3
"""Loopback-only v86 Ethernet relay using QEMU/libslirp, plus public desktop assets.

Bounded development preview: public ping, gateway DNS and TCP web only.
No TAP, forwarding sysctl, host port forwarding, or shared guest LAN is created.
"""
import argparse,asyncio,hashlib,ipaddress,json,os,re,resource,secrets,socket,struct,sys,time
from pathlib import Path
from dataclasses import dataclass
from aiohttp import web,WSMsgType,ClientSession,ClientTimeout,ClientError
ROOT=Path(__file__).resolve().parent.parent
RELAY_REVISION=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
sys.path.insert(0,str(ROOT))
from serve import PUBLIC,NETWORK,RUNTIME
from origin_service.mount import validate_base_path

def public_path(raw):
    parts=raw.split('/')
    if any(x in ('','.','..') for x in parts) or '\\' in raw or '\x00' in raw:raise web.HTTPNotFound()
    allowed=raw in PUBLIC or len(parts)>1 and parts[0]=='assets' or len(parts)==2 and parts[0]=='network' and parts[1] in NETWORK or len(parts)==3 and parts[:2]==['.build','v86'] and parts[2] in RUNTIME
    if not allowed:raise web.HTTPNotFound()
    target=ROOT
    for p in parts:
        target=target/p
        if target.is_symlink():raise web.HTTPNotFound()
    if not target.is_file() or not target.resolve().is_relative_to(ROOT):raise web.HTTPNotFound()
    return target

def permitted_frame(frame,preview=False):
    if not 14<=len(frame)<=1518:return False
    kind=int.from_bytes(frame[12:14],'big')
    if kind==0x0806:
        # Only resolve our gateway/DNS; each guest has its own isolated wire.
        return (len(frame)>=42 and frame[14:22]==b'\x00\x01\x08\x00\x06\x04\x00\x01'
                and frame[28:32]==socket.inet_aton('10.86.0.2')
                and frame[38:42] in (socket.inet_aton('10.86.0.1'),socket.inet_aton('10.86.0.3')))
    if kind!=0x0800 or len(frame)<34 or frame[14]>>4!=4:return False
    ihl=(frame[14]&15)*4;total=int.from_bytes(frame[16:18],'big')
    # IP options (including source routing), fragments and reserved flags are
    # unnecessary for this gateway and must not bypass destination filtering.
    if ihl!=20 or total<ihl or len(frame)<14+total:return False
    if int.from_bytes(frame[20:22],'big')&0xbfff:return False
    if frame[26:30]!=socket.inet_aton('10.86.0.2'):return False
    protocol=frame[23];destination=ipaddress.IPv4Address(frame[30:34])
    payload=frame[34:14+total]
    if protocol==1:
        if len(payload)<8 or payload[:2]!=b'\x08\x00':return False
    elif protocol==6:
        if len(payload)<20 or not 20<=((payload[12]>>4)*4)<=len(payload):return False
    elif protocol==17:
        if len(payload)<8 or int.from_bytes(payload[4:6],'big')!=len(payload):return False
    else:return False
    if destination==ipaddress.IPv4Address('10.86.0.3'):
        return protocol==17 and total>=ihl+8 and int.from_bytes(frame[16+ihl:18+ihl],'big')==53
    if preview and (protocol==17 or protocol==6 and int.from_bytes(payload[2:4],'big') not in (80,443)):return False
    return destination.is_global and not destination.is_multicast

def child_limits():
    resource.setrlimit(resource.RLIMIT_NOFILE,(256,256))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))

def require_ping_socket():
    """Fail before listening if the service cannot open an unprivileged ping socket."""
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_ICMP):pass
    except OSError as error:
        raise ValueError('Guest ping requires an allowed service group in net.ipv4.ping_group_range') from error

@dataclass(frozen=True)
class Limits:
    session_seconds:float=1800
    bytes_per_second:int=262144
    packets_per_second:int=200
    session_bytes:int=67108864

class SharedByteBudget:
    """One service-wide cap; exhausted until an explicit service restart."""
    def __init__(self,limit=268435456):self.limit=limit;self.used=0;self.exhausted=False
    def charge(self,size):
        if self.exhausted or self.used+size>self.limit:
            self.exhausted=True;raise ValueError('preview service data cap reached')
        self.used+=size
        if self.used==self.limit:self.exhausted=True

class TrafficBudget:
    def __init__(self,limits,clock=time.monotonic):
        self.limits=limits;self.clock=clock;self.started=self.window=clock()
        self.byte_count=self.packet_count=self.total_bytes=0
    def charge(self,size):
        current=self.clock()
        if current-self.started>=self.limits.session_seconds:raise ValueError('session expired')
        if current-self.window>=1:self.window=current;self.byte_count=self.packet_count=0
        self.byte_count+=size;self.packet_count+=1
        self.total_bytes+=size
        if self.total_bytes>self.limits.session_bytes:raise ValueError('session data cap reached')
        if self.byte_count>self.limits.bytes_per_second or self.packet_count>self.limits.packets_per_second:raise ValueError('rate limit')

class Relay:
    def __init__(self,origin,limits=None,identity_config_port=None,base_path='',cookie_secret=None):
        self.base_path=validate_base_path(base_path)
        if identity_config_port is not None and (type(identity_config_port) is not int or not 1<=identity_config_port<=65535):raise ValueError("Invalid issuer config port")
        self.identity_config_port=identity_config_port
        self.limits=limits or Limits();self.shared_budget=SharedByteBudget()
        if cookie_secret is not None and (not isinstance(cookie_secret,str) or not re.fullmatch(r'[A-Za-z0-9_-]{43,128}',cookie_secret)):raise ValueError('Invalid guest connection cookie')
        self.origin=origin;self.secret=cookie_secret if cookie_secret is not None else secrets.token_urlsafe(32);self.active=0;self.starts=[];self.forwarded=0;self.received=0;self.blocked=0
    async def configuration(self):
        if self.identity_config_port is None:config=json.loads((ROOT/'config.json').read_text())
        else:
            try:
                from urllib.parse import urlsplit
                async with ClientSession(timeout=ClientTimeout(total=2)) as client:
                    async with client.get('http://127.0.0.1:'+str(self.identity_config_port)+'/config.json',headers={'Host':urlsplit(self.origin).netloc},allow_redirects=False) as response:
                        if response.status!=200:raise ValueError('Issuer config unavailable')
                        raw=b''
                        async for chunk in response.content.iter_chunked(8192):
                            raw+=chunk
                            if len(raw)>65536:raise ValueError('Issuer config too large')
                        config=json.loads(raw)
                if not isinstance(config,dict) or not isinstance(config.get('identity'),dict):raise ValueError('Malformed issuer config')
                if config.get('identity',{}).get('mode')!='server' or config['identity'].get('issuer')!=self.origin:raise ValueError('Unexpected issuer config')
            except (ClientError,TimeoutError,ValueError,KeyError,TypeError):raise web.HTTPBadGateway(text='Configured development issuer unavailable') from None
        return config
    def network_metadata(self):
        return {'relayPath':self.base_path+'/guest-network','egress':'relay-host','relayRevision':RELAY_REVISION,'previewPolicy':{'version':'bounded-preview/1','tcpPorts':[80,443],'udp':'gateway-dns-only','icmp':'public-echo','sessionSeconds':self.limits.session_seconds,'sessionBytes':self.limits.session_bytes,'serviceBytes':self.shared_budget.limit,'serviceCapReset':'operator-restart','bytesPerSecond':self.limits.bytes_per_second,'packetsPerSecond':self.limits.packets_per_second,'concurrentGuests':4,'startsPerMinute':20}}
    async def assets(self,request):
        raw=request.match_info['path'] or 'index.html'
        if raw=='config.json':
            config=await self.configuration();config['guestNetwork']=self.network_metadata()
            return web.json_response(config,headers={'Cache-Control':'no-store'})
        response=web.FileResponse(public_path(raw));response.headers['Cache-Control']='no-store'
        if raw=='assets/desktop/offline-worker.js':response.headers['Service-Worker-Allowed']=self.base_path+'/'
        if raw=='index.html':response.set_cookie('codi_guest_relay',self.secret,httponly=True,samesite='Strict',secure=self.origin.startswith('https:'),max_age=3600,path=self.base_path+'/')
        return response
    async def relay(self,request):
        if request.headers.get('Origin')!=self.origin or not secrets.compare_digest(request.cookies.get('codi_guest_relay',''),self.secret):raise web.HTTPForbidden()
        now=time.monotonic();self.starts=[t for t in self.starts if now-t<60]
        if self.active>=4 or len(self.starts)>=20 or self.shared_budget.exhausted:raise web.HTTPServiceUnavailable(headers={'Retry-After':'60'})
        self.starts.append(now);self.active+=1;process=None;parent=None;tasks=[];ws=None
        try:
            parent,child=socket.socketpair();parent.setblocking(False)
            command=['qemu-system-i386','-machine','none','-nodefaults','-no-user-config','-display','none','-monitor','none','-serial','none','-m','16M','-netdev','user,id=wan,ipv6=off,net=10.86.0.0/24,host=10.86.0.1,dhcpstart=10.86.0.2,dns=10.86.0.3','-netdev',f'socket,id=wire,fd={child.fileno()}','-netdev','hubport,id=p0,hubid=0,netdev=wan','-netdev','hubport,id=p1,hubid=0,netdev=wire']
            try:process=await asyncio.create_subprocess_exec(*command,pass_fds=(child.fileno(),),stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL,preexec_fn=child_limits)
            finally:child.close()
            reader,writer=await asyncio.open_connection(sock=parent);parent=None
            ws=web.WebSocketResponse(max_msg_size=1518,compress=False,heartbeat=30);await ws.prepare(request)
            budget=TrafficBudget(self.limits)
            async def ingress():
                async for message in ws:
                    if message.type!=WSMsgType.BINARY:raise ValueError('binary Ethernet required')
                    frame=message.data;budget.charge(len(frame));self.shared_budget.charge(len(frame))
                    if not permitted_frame(frame,preview=True):self.blocked+=1;continue
                    writer.write(struct.pack('!I',len(frame))+frame);await asyncio.wait_for(writer.drain(),5);self.forwarded+=1
            async def egress():
                while True:
                    size=struct.unpack('!I',await reader.readexactly(4))[0]
                    if not 14<=size<=1518:raise ValueError('invalid backend frame')
                    frame=await reader.readexactly(size);budget.charge(size);self.shared_budget.charge(size);await asyncio.wait_for(ws.send_bytes(frame),5);self.received+=1
            tasks=[asyncio.create_task(ingress()),asyncio.create_task(egress()),asyncio.create_task(process.wait()),asyncio.create_task(asyncio.sleep(self.limits.session_seconds))]
            await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
            return ws
        finally:
            for task in tasks:task.cancel()
            if tasks:await asyncio.gather(*tasks,return_exceptions=True)
            if ws is not None:await ws.close()
            if 'writer' in locals():
                writer.close()
                try:await writer.wait_closed()
                except Exception:pass
            if parent is not None:parent.close()
            if process is not None and process.returncode is None:
                process.terminate()
                try:await asyncio.wait_for(process.wait(),3)
                except asyncio.TimeoutError:process.kill();await process.wait()
            self.active-=1

def main():
    p=argparse.ArgumentParser();p.add_argument('--port',type=int,default=8120);p.add_argument('--origin',required=True);p.add_argument('--identity-config-port',type=int,help='Optional separate loopback development issuer config source');p.add_argument('--base-path',default='',type=validate_base_path);p.add_argument('--require-ping',action='store_true',help='Refuse startup unless this service can open an unprivileged ICMP echo socket')
    p.add_argument('--cookie-secret-file',type=Path)
    p.add_argument('--network-control',type=Path,help='Explicit protected descriptor for private fixed-role networking')
    p.add_argument('--network-control-sha256');args=p.parse_args()
    if (args.network_control is None)!=(args.network_control_sha256 is None):p.error('Network descriptor and exact pin must be supplied together')
    if args.identity_config_port==args.port:p.error('Issuer and relay ports must differ')
    if args.require_ping:
        try:require_ping_socket()
        except ValueError as error:p.error(str(error))
    from origin_service.guest_cookie import load
    cookie=load(args.cookie_secret_file,ROOT) if args.cookie_secret_file is not None else None
    relay=Relay(args.origin,identity_config_port=args.identity_config_port,base_path=args.base_path,cookie_secret=cookie)
    if args.network_control is not None:
        try:
            from guest_service.runtime import load as load_frontend,credential
            from guest_service.frontend import ControlledFrontend
            descriptor=load_frontend(args.network_control,args.network_control_sha256)
            relay=ControlledFrontend(relay,descriptor,{role:credential(role+'-wire.secret') for role in ('anonymous','registered')})
        except (ValueError,OSError) as error:p.error(str(error))
    app=web.Application(client_max_size=16384);app.router.add_get('/guest-network',relay.relay);app.router.add_get('/{path:.*}',relay.assets)
    web.run_app(app,host='127.0.0.1',port=args.port,access_log=None)
if __name__=='__main__':main()
