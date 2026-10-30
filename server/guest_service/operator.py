"""Protected persistent guest worker/kernel lifecycle and fail-closed supervisor.

Configuration installs static units only. Start requires the existing frontend
to be stopped. No route, login data, guest cookie, boot policy or host sysctl is
changed here. Only this instance's exact scoped nft table can be removed.
"""
import asyncio
from contextlib import contextmanager
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import stat
import subprocess
import tempfile
import time

from .authorization import WireAuthorization
from .egress import EgressPolicy
from .installation import path,root_file,sha,verify_runtime,settings,units,semantic_kernel
from .usage import protected,Permissions,initialize_permissions

ROLES=('anonymous','registered')
OPERATOR_FILES=frozenset({*('guest_service/'+name+'.py' for name in ['__init__','authorization','egress','usage','installation','operator']),
    'codiserver-server-v0.3.0/codiauth/__init__.py','codiserver-server-v0.3.0/codiauth/jose.py','requirements.lock','scripts/manage-guest-network.py'})
CONFIG_FIELDS={'version','instance','unitDir','workerRelease','workerSHA256','operatorRelease','operatorSHA256','python','stateRoot','frontendUser','frontendUID','frontendUnit','pingGID','roles','origin','basePath','issuerPolicy','policy','policySHA256','namespacePath','namespaceInode','kernelSHA256','qemuSHA256','secretSHA256'}

def run(arguments,*,check=True,**kwargs):
    kwargs.setdefault('env',{key:value for key,value in os.environ.items() if key!='NOTIFY_SOCKET'})
    value=subprocess.run(list(map(str,arguments)),capture_output=True,text=True,timeout=45,**kwargs)
    if check and value.returncode:raise ValueError(value.stderr[-1500:] or 'Managed guest command failed')
    return value
def systemctl(*args,check=True):return run(['/usr/bin/systemctl',*args],check=check).stdout.strip()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def sync(folder):
    fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
def directory(value,mode=0o755,owner=0,gid=0):
    value=path(str(value))
    if not value.exists():
        protected(value.parent,0,0o755,directory=True);value.mkdir(mode=mode);os.chown(value,owner,gid);sync(value.parent)
    return protected(value,owner,mode,directory=True)
def atomic(file,raw,mode=0o600):
    file=path(str(file));protected(file.parent,0,0o755,directory=True)
    if file.exists() or file.is_symlink():root_file(file,mode=mode,maximum=1048576)
    fd,temporary=tempfile.mkstemp(prefix='.guest-operation-',dir=file.parent)
    try:
        with os.fdopen(fd,'wb') as stream:os.fchmod(stream.fileno(),mode);stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,file);sync(file.parent)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)
def write(file,value):atomic(file,encoded(value))
def account(name):
    who=pwd.getpwnam(name);group=grp.getgrgid(who.pw_gid)
    if who.pw_uid<=0 or who.pw_gid<=0 or len([v for v in pwd.getpwall() if v.pw_uid==who.pw_uid])!=1 or group.gr_name!=name or set(group.gr_mem)-{name} or who.pw_dir!='/nonexistent' or who.pw_shell!='/usr/sbin/nologin' or set(os.getgrouplist(name,who.pw_gid))!={who.pw_gid} or run(['/usr/bin/passwd','-S',name]).stdout.split()[1]!='L':raise ValueError('Dedicated locked non-login service account required')
    return who
def verify_operator(folder,pin=None):
    folder=protected(folder,0,0o755,directory=True);raw=root_file(folder/'guest-operator.json',pin=pin);value=json.loads(raw)
    if set(value)!={'version','files'} or value['version']!='codi-guest-network-operator/1' or set(value['files'])!=OPERATOR_FILES:raise ValueError('Sealed guest operator required')
    found=set()
    for file in folder.rglob('*'):
        if file.is_dir():protected(file,0,0o755,directory=True);continue
        name=str(file.relative_to(folder));found.add(name);data=root_file(file,maximum=262144)
        if name!='guest-operator.json' and value['files'].get(name)!={'bytes':len(data),'sha256':sha(data)}:raise ValueError('Guest operator input changed')
    if found!=OPERATOR_FILES|{'guest-operator.json'}:raise ValueError('Missing or extra guest operator file')
    return sha(raw)
def verify_python(python,release):
    python=Path(python);venv=protected(python.parent.parent,0,0o755,directory=True)
    if python.name!='python' or python.parent.name!='bin':raise ValueError('Installed protected virtualenv bin/python required')
    for item in venv.rglob('*'):
        info=item.lstat()
        if info.st_uid or not item.is_symlink() and info.st_mode&0o022:raise ValueError('Virtualenv custody changed')
        if item.is_symlink():
            target=item.resolve(strict=True)
            if not target.is_relative_to(venv):
                if item.parent!=venv/'bin' or not re.fullmatch(r'python(?:3(?:\.[0-9]+)?)?',item.name) or target.parent!=Path('/usr/bin') or not re.fullmatch(r'python3\.[0-9]+',target.name):raise ValueError('Unsafe virtualenv link')
                protected(target,0,0o755)
    expected={line for line in root_file(Path(release)/'requirements.lock').decode().splitlines() if line}
    if set(run([python,'-I','-B','-m','pip','freeze']).stdout.splitlines())!=expected:raise ValueError('Guest virtualenv dependency lock changed')
    run([python,'-I','-B','-m','pip','check'])

def namespace_prefix(c):
    namespace=c['namespacePath']
    if namespace is None:return []
    if not re.fullmatch(r'/run/netns/codi-ng-fixture-[0-9a-f]{8}',namespace):raise ValueError('Explicit fixture namespace required')
    info=Path(namespace).lstat()
    if info.st_uid or info.st_mode&0o022 or info.st_ino!=c['namespaceInode']:raise ValueError('Guest namespace custody changed')
    return [] if os.stat('/proc/self/ns/net').st_ino==info.st_ino else ['/usr/bin/nsenter','--net='+namespace]
def table_snapshot(c):
    value=run([*namespace_prefix(c),'/usr/sbin/nft','-j','list','tables'])
    entries=json.loads(value.stdout)['nftables']
    if not any(v.get('table',{}).get('family')=='inet' and v.get('table',{}).get('name')=='codi_guest_egress' for v in entries):return None
    data=json.loads(run([*namespace_prefix(c),'/usr/sbin/nft','-j','-a','list','table','inet','codi_guest_egress']).stdout)
    metadata=next(v['table'] for v in data['nftables'] if 'table' in v)
    if type(metadata.get('handle')) is not int or metadata['handle']<=0:raise ValueError('Kernel table generation handle required')
    return semantic_kernel(data),metadata['handle']
def table(c):
    snapshot=table_snapshot(c);return snapshot[0] if snapshot else None
def expected_kernel(python,operator,rules):
    # Compile the generated policy in a fresh, private kernel namespace BEFORE
    # touching the target namespace. Recovery already knows the expected shape.
    comments=re.findall(r'comment "(codi-guest-owner:[0-9a-f]{64})"',rules)
    if len(comments)!=1:raise ValueError('Explicit controller ownership marker required')
    code='import json,subprocess,sys;sys.path.insert(0,sys.argv[1]);from guest_service.installation import semantic_kernel;subprocess.run(["/usr/sbin/nft","-f","-"],input=sys.stdin.read(),text=True,check=True);data=json.loads(subprocess.check_output(["/usr/sbin/nft","-j","list","table","inet","codi_guest_egress"],text=True));meta=next(v["table"] for v in data["nftables"] if "table" in v);assert meta.get("comment")==sys.argv[2],"Kernel did not retain the controller ownership marker";print(semantic_kernel(data))'
    return run(['/usr/bin/unshare','--net',python,'-I','-B','-c',code,operator,comments[0]],input=rules).stdout.strip()

class Manager:
    def __init__(self,folder,operator):
        self.folder=path(str(folder));self.operator=path(str(operator));self.config=self.folder/'managed.json';self.pending=self.folder/'pending.json';self.active=self.folder/'active.json';self.fault=self.folder/'fault.json'
    @contextmanager
    def locked(self):
        if os.geteuid()!=0:raise ValueError('Root guest network controller required')
        directory(self.folder);global_dir=directory('/run/codi-network-operators',0o700);fds=[]
        try:
            for file in [global_dir/'global.lock',self.folder/'.operator.lock']:
                fd=os.open(file,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);fds.append(fd);info=os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError('Unsafe guest operator lock')
                try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:raise ValueError('Another guest network operation is in progress') from None
            yield
        finally:
            for fd in reversed(fds):os.close(fd)
    def clear(self,file):
        if file.exists():root_file(file,mode=0o600);file.unlink();sync(self.folder)
    def names(self,c):return [c['instance']+'-guard.service',*[c['instance']+'-'+role+'.'+suffix for role in ROLES for suffix in ['socket','service']]]
    def worker_settings(self,c,role):
        return {'version':'codi-guest-worker/1','role':role,'origin':c['origin'],'basePath':c['basePath'],'uid':c['roles'][role]['uid'],'pingGID':c['pingGID'],'frontendUID':c['frontendUID'],
            'socketPath':'/run/codi-network/'+c['instance']+'/'+role+'.sock','statePath':str(Path(c['stateRoot'])/role),'permissionsPath':str(self.folder/'policy/permissions.sqlite3'),
            'policy':c['policy'],'policySHA256':c['policySHA256'],'issuerPolicy':c['issuerPolicy'],'kernel':{'namespacePath':c['namespacePath'],'namespaceInode':c['namespaceInode'],'sha256':c['kernelSHA256']},'qemuSHA256':c['qemuSHA256'],'runtimeSHA256':c['workerSHA256']}
    def rendered(self,c):
        guard=c['instance']+'-guard.service';result={}
        for role in ROLES:
            output=units(instance=c['instance'],role=role,user=c['roles'][role]['user'],ping_gid=c['pingGID'],frontend_user=c['frontendUser'],release=c['workerRelease'],python=c['python'],settings_path=self.folder/(role+'.json'),settings_sha256=sha(encoded(self.worker_settings(c,role))),secret_path=self.folder/'credentials'/(role+'.secret'),state_path=Path(c['stateRoot'])/role,other_state_path=Path(c['stateRoot'])/('registered' if role=='anonymous' else 'anonymous'),socket_path='/run/codi-network/'+c['instance']+'/'+role+'.sock',resolver_path=self.folder/'resolv.conf',namespace=c['namespacePath'])
            for name,raw in output.items():
                marker=b'\n[Service]\n' if name.endswith('.service') else b'\n[Socket]\n'
                result[name]=raw.replace(marker,('\nBindsTo='+guard+'\nAfter='+guard+'\n').encode()+marker,1)
        command=[c['python'],'-I','-B',str(self.operator/'scripts/manage-guest-network.py'),'monitor','--config-dir',str(self.folder)]
        text='[Unit]\nDescription=Codi guest kernel and custody guard\n\n[Service]\nType=notify\nNotifyAccess=main\nUser=root\nGroup=root\nExecStart='+' '.join('"'+v+'"' for v in command)+'\n'
        values={'UMask':'0077','ProtectSystem':'strict','ProtectHome':'yes','PrivateTmp':'yes','PrivateDevices':'yes','NoNewPrivileges':'yes','ProtectKernelTunables':'yes','ProtectKernelModules':'yes','ProtectControlGroups':'yes','RestrictSUIDSGID':'yes','RestrictNamespaces':'yes','LockPersonality':'yes','RestrictAddressFamilies':'AF_UNIX AF_NETLINK','CapabilityBoundingSet':'CAP_NET_ADMIN','AmbientCapabilities':'','ReadWritePaths':str(self.folder),'InaccessiblePaths':'-/etc/codi-connected -/var/lib/codi-connected -/etc/codi-user-files -/var/lib/codi-user-files -/etc/caddy -/var/lib/caddy','MemoryMax':'96M','TasksMax':'32','LimitNOFILE':'128','Environment':'PYTHONDONTWRITEBYTECODE=1','Restart':'no','TimeoutStartSec':'20s','TimeoutStopSec':'15s'}
        if c['namespacePath']:values['NetworkNamespacePath']=c['namespacePath']
        result[guard]=(text+''.join(k+'='+v+'\n' for k,v in values.items())).encode();return result
    def validate_plan(self,c):
        if not isinstance(c,dict) or set(c)!=CONFIG_FIELDS or c['version']!='codi-guest-managed/1' or not re.fullmatch(r'codi-net-[a-z0-9][a-z0-9-]{0,35}',c['instance']) or c['unitDir'] not in ('/etc/systemd/system','/run/systemd/system'):raise ValueError('Exact guest controller config required')
        if c['operatorRelease']!=str(self.operator) or verify_operator(self.operator)!=c['operatorSHA256']:raise ValueError('Different guest controller runtime')
        verify_runtime(c['workerRelease'],c['workerSHA256'])
        roots=[self.folder,path(c['workerRelease']),self.operator,path(c['stateRoot']),path(str(Path(c['python']).parent.parent))]
        if any(a.is_relative_to(b) or b.is_relative_to(a) for i,a in enumerate(roots) for b in roots[i+1:]) or any(p.is_relative_to(Path(base)) for p in roots for base in ['/home','/root','/tmp','/var/tmp','/run']):raise ValueError('Disjoint persistent code, config, state and environment roots required')
        for folder in roots:
            if folder.exists():protected(folder,0,0o755,directory=True)
            elif folder==Path(c['stateRoot']):protected(folder.parent,0,0o755,directory=True)
            else:raise ValueError('Prepared protected guest install roots required')
        fixture=c['namespacePath'] is not None
        if fixture and (not isinstance(c['namespacePath'],str) or not re.fullmatch(r'/run/netns/codi-ng-fixture-[0-9a-f]{8}',c['namespacePath']) or c['unitDir']!='/run/systemd/system'):raise ValueError('Runtime-only private fixture required')
        if c['frontendUnit']!=(None if fixture else 'codi-'+c['instance'].removeprefix('codi-net-')+'-guest.service') or (not re.fullmatch(r'codi-ngf-f-[0-9a-f]{8}',c['frontendUser']) if fixture else c['frontendUser']!='codi-guest'):raise ValueError('Exact prepared guest frontend required')
        front=account(c['frontendUser'])
        if front.pw_uid!=c['frontendUID'] or type(c['pingGID']) is not int or c['pingGID']!=1001 or grp.getgrgid(1001).gr_name!='codi-guest':raise ValueError('Existing scoped frontend/ping identity changed')
        if set(c['roles'])!=set(ROLES) or set(c['secretSHA256'])!=set(ROLES):raise ValueError('Exactly two fixed workers required')
        ids=[front.pw_uid]
        for role in ROLES:
            who=c['roles'][role]
            if set(who)!={'user','uid','gid'} or (not re.fullmatch(r'codi-ngf-[ar]-[0-9a-f]{8}',who['user']) if fixture else who['user']!='codi-net-'+role):raise ValueError('Prepared fixed-role worker required')
            identity=account(who['user']);ids.append(identity.pw_uid)
            if [identity.pw_uid,identity.pw_gid]!=[who['uid'],who['gid']] or not re.fullmatch('[0-9a-f]{64}',c['secretSHA256'][role]):raise ValueError('Worker identity or credential pin changed')
        if len(set(ids))!=3:raise ValueError('Three separate service identities required')
        public=c['issuerPolicy']
        if not isinstance(public,dict) or set(public)!={'mode','apiBase','issuer','audience','authorityClass','authorityKeys'} or public['mode']!='server' or public['apiBase']!=c['basePath']+'/api/v1' or public['issuer']!=c['origin'] or public['audience']!='codiserver-peers-v1' or public['authorityClass']!='development':raise ValueError('Public development issuer context required')
        if not isinstance(public['authorityKeys'],list) or not 1<=len(public['authorityKeys'])<=4:raise ValueError('Explicit public issuer keys required')
        for entry in public['authorityKeys']:
            if set(entry)!={'kid','jwk'} or set(entry['jwk'])!={'kty','crv','x','y'}:raise ValueError('Only public issuer keys may enter worker settings')
        policy=EgressPolicy.parse(c['policy'])
        if policy.sha256!=c['policySHA256']:raise ValueError('Effective guest egress policy changed')
        WireAuthorization(public,policy.sha256,base_path=c['basePath'])
        if type(c['namespaceInode']) is not int or os.stat(c['namespacePath'] or '/proc/self/ns/net').st_ino!=c['namespaceInode']:raise ValueError('Guest target namespace changed')
        for name in ['kernelSHA256','qemuSHA256']:
            if not isinstance(c[name],str) or not re.fullmatch('[0-9a-f]{64}',c[name]):raise ValueError('Pinned guest kernel/runtime required')
    def validate(self,c,*,full=True):
        self.validate_plan(c)
        if c['operatorRelease']!=str(self.operator) or verify_operator(self.operator)!=c['operatorSHA256']:raise ValueError('Different guest controller runtime')
        verify_runtime(c['workerRelease'],c['workerSHA256'])
        if full:verify_python(c['python'],c['workerRelease'])
        roots=[self.folder,path(c['workerRelease']),self.operator,path(c['stateRoot']),Path(c['python']).parent.parent]
        if any(a.is_relative_to(b) or b.is_relative_to(a) for i,a in enumerate(roots) for b in roots[i+1:]) or any(p.is_relative_to(Path(base)) for p in roots for base in ['/home','/root','/tmp','/var/tmp','/run']):raise ValueError('Disjoint persistent code, config, state and environment roots required')
        for folder in roots:protected(folder,0,0o755,directory=True)
        fixture=c['namespacePath'] is not None
        if fixture and (not re.fullmatch(r'/run/netns/codi-ng-fixture-[0-9a-f]{8}',c['namespacePath']) or c['unitDir']!='/run/systemd/system'):raise ValueError('Runtime-only private fixture required')
        expected_front='codi-'+c['instance'].removeprefix('codi-net-')+'-guest.service'
        if c['frontendUnit']!=(None if fixture else expected_front):raise ValueError('Exact existing guest frontend unit required')
        if c['pingGID']!=1001 or grp.getgrgid(1001).gr_name!='codi-guest':raise ValueError('Existing scoped guest ping GID required')
        front=account(c['frontendUser'])
        if front.pw_uid!=c['frontendUID'] or not fixture and c['frontendUser']!='codi-guest':raise ValueError('Prepared frontend identity changed')
        if set(c['roles'])!=set(ROLES) or set(c['secretSHA256'])!=set(ROLES):raise ValueError('Exactly two fixed workers required')
        ids=[front.pw_uid]
        for role in ROLES:
            who=c['roles'][role]
            if set(who)!={'user','uid','gid'} or not fixture and who['user']!='codi-net-'+role or fixture and not re.fullmatch(r'codi-ngf-[ar]-[0-9a-f]{8}',who['user']):raise ValueError('Prepared fixed-role service account required')
            identity=account(who['user']);ids.append(identity.pw_uid)
            if [identity.pw_uid,identity.pw_gid]!=[who['uid'],who['gid']]:raise ValueError('Guest worker service identity changed')
            protected(Path(c['stateRoot'])/role,who['uid'],0o700,directory=True)
            if full:protected(Path(c['stateRoot'])/role/'usage.sqlite3',who['uid'],0o600)
            if sha(root_file(self.folder/'credentials'/(role+'.secret'),mode=0o600))!=c['secretSHA256'][role]:raise ValueError('Guest transport credential changed')
            raw=root_file(self.folder/(role+'.json'))
            if raw!=encoded(self.worker_settings(c,role)):raise ValueError('Guest worker settings changed')
            settings(self.folder/(role+'.json'),sha(raw));WireAuthorization(c['issuerPolicy'],c['policySHA256'],base_path=c['basePath'])
        if len(set(ids))!=3:raise ValueError('Three separate network role UIDs required')
        policy=EgressPolicy.parse(c['policy'])
        if policy.sha256!=c['policySHA256'] or c['issuerPolicy']['issuer']!=c['origin']:raise ValueError('Guest issuer/egress context changed')
        if root_file(self.folder/'resolv.conf')!=(''.join('nameserver '+v+'\n' for v in policy.dns_ipv4)).encode():raise ValueError('Public-only resolver changed')
        if full:
            for role in ROLES:Permissions(self.folder/'policy/permissions.sqlite3').defaults(role)
            if sha(root_file('/usr/bin/qemu-system-i386',mode=0o755,maximum=67108864))!=c['qemuSHA256']:raise ValueError('Guest QEMU binary changed')
        if os.stat(c['namespacePath'] or '/proc/self/ns/net').st_ino!=c['namespaceInode']:raise ValueError('Guest target namespace changed')
    def check_units(self,c):
        for name,expected in self.rendered(c).items():
            file=Path(c['unitDir'])/name
            if root_file(file)!=expected:raise ValueError('Guest unit input changed')
            for root in ['/etc/systemd/system','/run/systemd/system','/usr/lib/systemd/system']:
                extra=Path(root)/(name+'.d');other=Path(root)/name
                if extra.exists() or extra.is_symlink() or other!=file and (other.exists() or other.is_symlink()):raise ValueError('Ambiguous guest unit/drop-in')
            value=dict(v.split('=',1) for v in systemctl('show',name,'-p','FragmentPath','-p','DropInPaths','-p','UnitFileState').splitlines())
            if value['FragmentPath']!=str(file) or value['DropInPaths'] or value['UnitFileState'] not in ('static','disabled'):raise ValueError('Loaded guest unit differs or boot policy changed')
    def load(self,*,pending=False,full=True):
        if not pending and self.pending.exists():raise ValueError('Recover pending guest network operation first')
        c=json.loads(root_file(self.config,mode=0o600));self.validate(c,full=full);self.check_units(c);return c
    def states(self,c):
        return {name:dict(v.split('=',1) for v in systemctl('show',name,'-p','ActiveState','-p','MainPID','-p','UnitFileState').splitlines()) for name in self.names(c)}
    def frontend_down(self,c):
        if c['frontendUnit'] and systemctl('show',c['frontendUnit'],'-p','MainPID','--value')!='0':raise ValueError('Stop the existing frontend before guest network activation or kernel removal')
    def all_down(self,c):
        for value in self.states(c).values():
            if value['ActiveState'] not in ('inactive','failed') or int(value.get('MainPID','0')):raise ValueError('Guest units must be stopped')
    def rules(self,c):
        raw=EgressPolicy.parse(c['policy']).nftables(anonymous_uid=c['roles']['anonymous']['uid'],registered_uid=c['roles']['registered']['uid'],frontend_uid=c['frontendUID'],unix_workers=True)
        owner=sha(encoded({'instance':c['instance'],'configDir':str(self.folder)}))
        # Exclusive create and the complete ruleset are one nft transaction.
        # A competing table appearing after inspection cannot be adopted.
        return 'create table inet codi_guest_egress { comment "codi-guest-owner:'+owner+'"; }\n'+raw
    def halt(self,c,*,frontend=False):
        if frontend and c['frontendUnit']:systemctl('stop',c['frontendUnit'])
        systemctl('stop',*reversed(self.names(c)))
        self.all_down(c)
    def remove_kernel(self,c,phase=lambda name:None):
        snapshot=table_snapshot(c)
        if snapshot is None:return
        if snapshot[0]!=c['kernelSHA256']:raise ValueError('Unmanaged kernel drift retained; refusing table removal')
        phase('remove-checked')
        # Refer to the inspected generation, not a possibly reused table name.
        run([*namespace_prefix(c),'/usr/sbin/nft','delete','table','inet','handle',str(snapshot[1])])
    def configure(self,*,instance,worker,worker_sha256,python,state_root,frontend_user,anonymous_user,registered_user,issuer_policy,policy,namespace=None,unit_dir='/etc/systemd/system',base_path='',phase=lambda name:None):
        if self.pending.exists():raise ValueError('Recover existing guest journal first')
        if self.config.exists():
            c=self.load();requested={'instance':instance,'workerRelease':str(worker),'workerSHA256':worker_sha256,'python':str(python),'stateRoot':str(state_root),'frontendUser':frontend_user,'issuerPolicy':json.loads(root_file(issuer_policy)),'policy':EgressPolicy.parse(policy).value(),'namespacePath':namespace,'unitDir':unit_dir,'basePath':base_path}
            if any(c[key]!=value for key,value in requested.items()) or [c['roles'][role]['user'] for role in ROLES]!=[anonymous_user,registered_user]:raise ValueError('Existing guest configuration differs; explicit migration required')
            return {'status':'already-configured','started':False,'credentialsRegenerated':False}
        if not re.fullmatch(r'codi-net-[a-z0-9][a-z0-9-]{0,35}',instance):raise ValueError('Bounded guest instance required')
        operator_sha=verify_operator(self.operator);verify_runtime(worker,worker_sha256);verify_python(python,worker)
        for root in [self.folder,path(str(state_root)),path(str(worker)),self.operator,Path(python).parent.parent]:
            if any(root.is_relative_to(Path(v)) for v in ['/home','/root','/tmp','/var/tmp','/run']):raise ValueError('Persistent protected guest roots required')
        root_roles={role:{'user':name,'uid':account(name).pw_uid,'gid':account(name).pw_gid} for role,name in [('anonymous',anonymous_user),('registered',registered_user)]}
        front=account(frontend_user);public=json.loads(root_file(issuer_policy));egress=EgressPolicy.parse(policy)
        namespace_inode=os.stat(namespace or '/proc/self/ns/net').st_ino
        c={'version':'codi-guest-managed/1','instance':instance,'unitDir':unit_dir,'workerRelease':str(path(str(worker))),'workerSHA256':worker_sha256,'operatorRelease':str(self.operator),'operatorSHA256':operator_sha,'python':str(path(str(python))),'stateRoot':str(path(str(state_root))),'frontendUser':frontend_user,'frontendUID':front.pw_uid,'frontendUnit':None if namespace else 'codi-'+instance.removeprefix('codi-net-')+'-guest.service','pingGID':1001,'roles':root_roles,'origin':public['issuer'],'basePath':base_path,'issuerPolicy':public,'policy':egress.value(),'policySHA256':egress.sha256,'namespacePath':namespace,'namespaceInode':namespace_inode,'kernelSHA256':'','qemuSHA256':sha(root_file('/usr/bin/qemu-system-i386',mode=0o755,maximum=67108864)),'secretSHA256':{}}
        WireAuthorization(public,egress.sha256,base_path=base_path)
        c['kernelSHA256']=expected_kernel(python,self.operator,self.rules(c));tokens={role:secrets.token_urlsafe(32) for role in ROLES};c['secretSHA256']={role:sha(token.encode()) for role,token in tokens.items()}
        self.validate_plan(c)
        write(self.pending,{'version':'codi-guest-operation/1','kind':'configure','phase':'prepared','candidate':c,'tokens':tokens});phase('prepared');return self.finish_configure(c,tokens,phase)
    def finish_configure(self,c,tokens,phase=lambda name:None):
        self.validate_plan(c)
        if set(tokens)!=set(ROLES) or any(not re.fullmatch('[A-Za-z0-9_-]{43}',v) or sha(v.encode())!=c['secretSHA256'][role] for role,v in tokens.items()):raise ValueError('Pending guest credential custody changed')
        directory(c['stateRoot']);credentials=self.folder/'credentials'
        if not credentials.exists():credentials.mkdir(mode=0o700);sync(self.folder)
        protected(credentials,0,0o700,directory=True)
        for role in ROLES:
            secret=credentials/(role+'.secret')
            if secret.exists():
                if root_file(secret,mode=0o600)!=tokens[role].encode():raise ValueError('Retained guest credential differs')
            else:
                # Credentials directory is deliberately private rather than755.
                fd=os.open(secret,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as stream:stream.write(tokens[role].encode());stream.flush();os.fsync(stream.fileno())
                sync(credentials)
            who=c['roles'][role];folder=directory(Path(c['stateRoot'])/role,0o700,who['uid'],who['gid']);db=folder/'usage.sqlite3'
            code='import sys;from pathlib import Path;sys.path.insert(0,sys.argv[1]);from guest_service.usage import initialize_usage,UsageLedger,Permissions;path=Path(sys.argv[2]);initialize_usage(path,sys.argv[3])'
            if not db.exists():run(['/usr/bin/setpriv','--reuid='+str(who['uid']),'--regid=1001','--clear-groups','--bounding-set=-all','--no-new-privs',c['python'],'-I','-B','-c',code,c['workerRelease'],db,role])
        policy_dir=self.folder/'policy'
        if not policy_dir.exists():policy_dir.mkdir(mode=0o700);sync(self.folder)
        info=policy_dir.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid or stat.S_IMODE(info.st_mode) not in (0o700,0o755):raise ValueError('Protected network permission directory required')
        permission_path=policy_dir/'permissions.sqlite3'
        if not permission_path.exists():initialize_permissions(permission_path)
        policy_dir.chmod(0o755);protected(policy_dir,0,0o755,directory=True)
        for role in ROLES:
            Permissions(permission_path).defaults(role);atomic(self.folder/(role+'.json'),encoded(self.worker_settings(c,role)),0o644)
        resolver=''.join('nameserver '+ip+'\n' for ip in EgressPolicy.parse(c['policy']).dns_ipv4).encode();atomic(self.folder/'resolv.conf',resolver,0o644)
        self.validate(c);phase('inputs')
        for name,raw in self.rendered(c).items():
            file=Path(c['unitDir'])/name
            if file.exists() and root_file(file)!=raw:raise ValueError('Refusing to replace an unmanaged guest unit')
            atomic(file,raw,0o644)
        write(self.config,c);systemctl('daemon-reload');self.check_units(c);self.all_down(c);phase('units')
        write(self.pending,{'version':'codi-guest-operation/1','kind':'configure','phase':'committed','candidate':c,'tokens':tokens});phase('committed');self.clear(self.pending)
        return {'status':'configured','bootEnabled':False,'started':False,'policySHA256':c['policySHA256']}
    async def health(self,c):
        from aiohttp import ClientSession,ClientTimeout,UnixConnector
        for role in ROLES:
            secret=root_file(self.folder/'credentials'/(role+'.secret'),mode=0o600).decode()
            async with ClientSession(connector=UnixConnector(path=self.worker_settings(c,role)['socketPath']),timeout=ClientTimeout(total=2)) as client:
                async with client.get('http://localhost/healthz',headers={'Origin':c['origin'],'Authorization':'Codi-Wire '+secret}) as response:
                    value=await response.json()
                    if response.status!=200 or value!={'status':'ok','role':role,'policy_sha256':c['policySHA256'],'durable_usage':True}:raise ValueError('Protected guest worker not ready')
    def start(self,phase=lambda name:None):
        c=self.load()
        if self.fault.exists():raise ValueError('Recover recorded guest protection fault before restart')
        if self.active.exists():
            if json.loads(root_file(self.active,mode=0o600))!={'version':'codi-guest-active/1','configSHA256':sha(encoded(c))} or table(c)!=c['kernelSHA256'] or any(v['ActiveState']!='active' for v in self.states(c).values()):raise ValueError('Active guest protection state changed')
            asyncio.run(self.health(c));return {'status':'already-started','bootEnabled':False}
        self.frontend_down(c)
        self.all_down(c)
        if table(c) is not None:raise ValueError('Existing guest kernel table is not adopted')
        tuning=run([*namespace_prefix(c),'/usr/bin/cat','/proc/sys/net/ipv4/ping_group_range','/proc/sys/net/ipv4/ip_forward']).stdout.split()
        if len(tuning)!=3 or not int(tuning[0])<=1001<=int(tuning[1]) or tuning[2]!='0':raise ValueError('Existing scoped ping permission/disabled forwarding required')
        journal={'version':'codi-guest-operation/1','kind':'start','phase':'prepared','candidate':c};write(self.pending,journal);phase('prepared')
        try:
            run([*namespace_prefix(c),'/usr/sbin/nft','--check','-f','-'],input=self.rules(c));run([*namespace_prefix(c),'/usr/sbin/nft','-f','-'],input=self.rules(c))
            if table(c)!=c['kernelSHA256']:raise ValueError('Applied guest rules differ from generated policy')
            journal['phase']='kernel';write(self.pending,journal);phase('kernel')
            systemctl('reset-failed',*self.names(c),check=False);systemctl('start',c['instance']+'-guard.service');phase('guard')
            for role in ROLES:systemctl('start',c['instance']+'-'+role+'.service')
            deadline=time.monotonic()+15
            while True:
                try:asyncio.run(self.health(c));break
                except (OSError,ValueError,asyncio.TimeoutError):
                    if time.monotonic()>deadline:raise ValueError('Guest worker readiness failed')
                    time.sleep(.1)
            phase('workers');write(self.active,{'version':'codi-guest-active/1','configSHA256':sha(encoded(c))});journal['phase']='committed';write(self.pending,journal);phase('committed');self.clear(self.pending)
            return {'status':'started','bootEnabled':False,'units':self.states(c)}
        except Exception:
            self.halt(c);self.remove_kernel(c);self.clear(self.active);self.clear(self.pending);raise
    def stop(self,phase=lambda name:None):
        c=self.load()
        if not self.active.exists() and not self.fault.exists() and table(c) is None:
            self.all_down(c);return {'status':'already-stopped','usageAndCredentialsPreserved':True,'kernelTableRemoved':False}
        self.frontend_down(c);journal={'version':'codi-guest-operation/1','kind':'stop','phase':'prepared','candidate':c};write(self.pending,journal);phase('prepared')
        self.halt(c);phase('units');self.remove_kernel(c,phase);phase('kernel');self.clear(self.active);self.clear(self.fault);self.clear(self.pending)
        return {'status':'stopped','usageAndCredentialsPreserved':True,'kernelTableRemoved':True}
    def recover(self):
        if not self.pending.exists():
            c=self.load()
            if not self.fault.exists() and not self.active.exists():return {'status':'nothing-to-recover'}
            if not self.fault.exists() and json.loads(root_file(self.active,mode=0o600))=={'version':'codi-guest-active/1','configSHA256':sha(encoded(c))} and table(c)==c['kernelSHA256'] and all(v['ActiveState']=='active' for v in self.states(c).values()):
                try:
                    asyncio.run(self.health(c));return {'status':'already-started','usageAndCredentialsPreserved':True}
                except (OSError,ValueError):pass
            self.frontend_down(c)
            write(self.pending,{'version':'codi-guest-operation/1','kind':'stop','phase':'prepared','candidate':c})
        j=json.loads(root_file(self.pending,mode=0o600));c=j.get('candidate')
        if j.get('version')!='codi-guest-operation/1' or j.get('kind') not in ('configure','start','stop') or j.get('phase') not in ('prepared','inputs','units','kernel','committed'):raise ValueError('Unrecognized guest journal retained for review')
        if j['kind']=='configure':
            if set(j)!={'version','kind','phase','candidate','tokens'}:raise ValueError('Unexpected configure recovery record')
            return self.finish_configure(c,j['tokens'])
        if set(j)!={'version','kind','phase','candidate'}:raise ValueError('Unexpected guest activation recovery record')
        live=self.load(pending=True)
        if c!=live:raise ValueError('Guest journal/config mismatch retained')
        self.frontend_down(c)
        if j['kind']=='start' and j['phase']=='committed':
            healthy=table(c)==c['kernelSHA256'] and self.active.exists() and not self.fault.exists() and all(v['ActiveState']=='active' for v in self.states(c).values())
            if healthy:
                try:asyncio.run(self.health(c))
                except (OSError,ValueError):healthy=False
            if healthy:self.clear(self.pending);return {'status':'committed-start-retained','usageAndCredentialsPreserved':True}
        self.halt(c);self.remove_kernel(c);self.clear(self.active);self.clear(self.fault);self.clear(self.pending)
        return {'status':'stopped-recovered','usageAndCredentialsPreserved':True}
    def monitor(self):
        c=self.load(pending=True,full=False);baseline=sha(root_file(self.config,mode=0o600))
        def allowed():
            if self.fault.exists():raise ValueError('Recorded guest guard fault requires recovery')
            if self.pending.exists():
                j=json.loads(root_file(self.pending,mode=0o600))
                if j.get('kind')=='stop':return False
                if set(j)!={'version','kind','phase','candidate'} or j['version']!='codi-guest-operation/1' or j['kind']!='start' or j['phase'] not in ('prepared','kernel','committed') or j['candidate']!=c:raise ValueError('Unexpected operation during guest guard')
            elif not self.active.exists() or json.loads(root_file(self.active,mode=0o600))!={'version':'codi-guest-active/1','configSHA256':baseline}:raise ValueError('No matching active guest kernel lease')
            return True
        try:
            if not allowed():return
            if table(c)!=c['kernelSHA256']:raise ValueError('Guest kernel protection changed')
            notify=os.environ.get('NOTIFY_SOCKET')
            if not notify:raise ValueError('Managed guest guard notification socket required')
            with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as channel:channel.connect('\0'+notify[1:] if notify.startswith('@') else notify);channel.sendall(b'READY=1')
            while allowed():
                if sha(root_file(self.config,mode=0o600))!=baseline:raise ValueError('Guest guard configuration changed')
                self.validate(c,full=False);self.check_units(c)
                if table(c)!=c['kernelSHA256']:raise ValueError('Guest kernel protection changed')
                time.sleep(.5)
        except BaseException:
            # Stop from the previously validated config, not new/untrusted input.
            try:write(self.fault,{'version':'codi-guest-guard-fault/1','configSHA256':baseline,'at':int(time.time())})
            finally:self.halt(c,frontend=True)
            raise
