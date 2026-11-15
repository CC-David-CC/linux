"""Pinned worker inputs, root kernel preflight and static Unix socket units.

These primitives do not install or activate production networking. The managed
operator must coordinate the existing frontend, kernel journal and rollback.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from .authorization import context,policy_hash
from .egress import EgressPolicy
from .usage import protected

WORKER_FILES=frozenset({*('guest_service/'+name+'.py' for name in ['__init__','authorization','egress','frames','worker','unix_transport','usage','installation']),
    'scripts/serve-guest-wire.py','codiserver-server-v0.3.0/codiauth/__init__.py','codiserver-server-v0.3.0/codiauth/jose.py','requirements.lock'})

def sha(raw):return hashlib.sha256(raw).hexdigest()
def root_file(path,*,pin=None,mode=0o644,maximum=65536):
    path=protected(path,0,mode)
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as file:
        info=os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=mode or info.st_size>maximum:raise ValueError('Bounded root-owned worker input required')
        raw=file.read(maximum+1)
    if len(raw)>maximum or pin is not None and sha(raw)!=policy_hash(pin):raise ValueError('Worker input pin changed')
    return raw

def path(value):
    if not isinstance(value,str) or not re.fullmatch(r'/[A-Za-z0-9_./-]+',value) or any(p in ('','.','..') for p in value.split('/')[1:]):raise ValueError('Canonical worker installation path required')
    return Path(value)

def verify_runtime(folder,pin):
    folder=protected(folder,0,0o755,directory=True);value=json.loads(root_file(folder/'guest-wire.json',pin=pin))
    if not isinstance(value,dict) or set(value)!={'version','files'} or value['version']!='codi-guest-wire-runtime/1' or set(value['files'])!=WORKER_FILES:raise ValueError('Exact guest worker runtime manifest required')
    found=set()
    for file in folder.rglob('*'):
        if file.is_dir():protected(file,0,0o755,directory=True);continue
        name=str(file.relative_to(folder));found.add(name)
        raw=root_file(file,maximum=262144)
        if name!='guest-wire.json' and value['files'].get(name)!={'bytes':len(raw),'sha256':sha(raw)}:raise ValueError('Guest worker runtime input changed')
    if found!=WORKER_FILES|{'guest-wire.json'}:raise ValueError('Missing or extra guest worker input')

def settings(file,pin):
    value=json.loads(root_file(file,pin=pin))
    expected={'version','role','origin','basePath','uid','pingGID','frontendUID','socketPath','statePath','permissionsPath','policy','policySHA256','issuerPolicy','kernel','qemuSHA256','runtimeSHA256'}
    if not isinstance(value,dict) or set(value)!=expected or value['version']!='codi-guest-worker/1' or value['role'] not in ('anonymous','registered'):raise ValueError('Exact fixed-role worker settings required')
    for key in ['uid','pingGID','frontendUID']:
        if type(value[key]) is not int or not 1<=value[key]<=4294967294:raise ValueError('Explicit unprivileged worker identities required')
    if value['uid']==value['frontendUID']:raise ValueError('Separate frontend and worker UIDs required')
    context(value['origin'],value['basePath'])
    policy=EgressPolicy.parse(value['policy'])
    if policy.sha256!=value['policySHA256']:raise ValueError('Effective worker egress policy pin changed')
    issuer=value['issuerPolicy']
    if not isinstance(issuer,dict) or set(issuer)!={'mode','apiBase','issuer','audience','authorityClass','authorityKeys'} or issuer['mode']!='server' or issuer['issuer']!=value['origin'] or issuer['apiBase']!=value['basePath']+'/api/v1' or issuer['authorityClass']!='development' or issuer['audience']!='codiserver-peers-v1':raise ValueError('Pinned public development issuer policy required')
    if not isinstance(issuer['authorityKeys'],list) or not 1<=len(issuer['authorityKeys'])<=4:raise ValueError('Bounded explicit issuer keys required')
    for entry in issuer['authorityKeys']:
        if not isinstance(entry,dict) or set(entry)!={'kid','jwk'} or not isinstance(entry['jwk'],dict) or set(entry['jwk'])!={'kty','crv','x','y'}:raise ValueError('Only public issuer keys may enter worker settings')
    for name in ['socketPath','statePath','permissionsPath']:path(value[name])
    if not str(value['socketPath']).startswith('/run/codi-network/'):raise ValueError('Reserved runtime worker socket required')
    protected(value['statePath'],value['uid'],0o700,directory=True)
    root_file(value['permissionsPath'],maximum=1048576)
    kernel=value['kernel']
    if not isinstance(kernel,dict) or set(kernel)!={'namespacePath','namespaceInode','sha256'} or type(kernel['namespaceInode']) is not int or kernel['namespaceInode']<=0:raise ValueError('Pinned kernel namespace and rules required')
    policy_hash(kernel['sha256']);policy_hash(value['qemuSHA256']);policy_hash(value['runtimeSHA256'])
    if kernel['namespacePath'] is not None and not re.fullmatch(r'/run/netns/codi-ng-fixture-[0-9a-f]{8}',kernel['namespacePath']):raise ValueError('Only the explicit disposable fixture namespace may replace the host namespace')
    return value

def semantic_kernel(value):
    # Handles and counters vary while rules are in use. Rule order, expression
    # values, UID/address/port sets and all other fields must match exactly.
    def clean(item):
        if isinstance(item,list):return [clean(v) for v in item]
        if isinstance(item,dict):
            return {k:({} if k=='counter' and isinstance(v,dict) else clean(v)) for k,v in item.items() if k!='handle'}
        return item
    if not isinstance(value,dict) or set(value)!={'nftables'} or not isinstance(value['nftables'],list):raise ValueError('Exact nftables table witness required')
    selected=[]
    for entry in value['nftables']:
        if set(entry)=={'metainfo'}:continue
        if len(entry)!=1 or next(iter(entry)) not in ('table','set','chain','rule'):raise ValueError('Unexpected kernel table object')
        selected.append(clean(entry))
    if not selected or selected[0].get('table',{}).get('name')!='codi_guest_egress':raise ValueError('Scoped guest table witness required')
    return sha(json.dumps(selected,sort_keys=True,separators=(',',':')).encode())

def kernel_witness(namespace=None):
    if os.geteuid()!=0:raise ValueError('Root kernel preflight required')
    prefix=[]
    if namespace is not None:
        if not re.fullmatch(r'/run/netns/codi-ng-fixture-[0-9a-f]{8}',namespace):raise ValueError('Explicit private fixture namespace required')
        info=path(namespace).lstat()
        if info.st_uid or info.st_mode&0o022:raise ValueError('Private kernel namespace custody changed')
        prefix=['/usr/bin/nsenter','--net='+namespace]
    result=subprocess.run([*prefix,'/usr/sbin/nft','-j','list','table','inet','codi_guest_egress'],capture_output=True,text=True,timeout=10)
    if result.returncode:raise ValueError('Required scoped guest kernel table is unavailable')
    return semantic_kernel(json.loads(result.stdout))

def check_kernel(value):
    kernel=value['kernel'];namespace=kernel['namespacePath']
    if os.stat(namespace or '/proc/self/ns/net').st_ino!=kernel['namespaceInode'] or kernel_witness(namespace)!=kernel['sha256']:raise ValueError('Guest kernel rules or namespace changed; refusing worker start')

def credential():
    folder=Path(os.environ.get('CREDENTIALS_DIRECTORY',''))
    if not re.fullmatch(r'/run/credentials/codi-net-[a-z0-9-]+\.service',str(folder)):raise ValueError('Managed systemd worker credential required')
    file=folder/'wire.secret'
    for parent in folder.parents:
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid or info.st_mode&0o022:raise ValueError('Protected systemd credential ancestors required')
    directory=folder.lstat();info=file.lstat()
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid!=directory.st_gid or directory.st_uid!=0 or stat.S_IMODE(directory.st_mode)!=0o550 or not stat.S_ISREG(info.st_mode) or info.st_uid!=info.st_gid or info.st_uid!=0 or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o440 or not os.statvfs(file).f_flag&os.ST_RDONLY:raise ValueError('Read-only systemd worker credential required')
    with os.fdopen(os.open(file,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:raw=stream.read(129)
    if not re.fullmatch(rb'[A-Za-z0-9_-]{43,128}',raw):raise ValueError('Bounded worker transport secret required')
    return raw.decode('ascii')

def units(*,instance,role,user,ping_gid,frontend_user,release,python,settings_path,settings_sha256,secret_path,state_path,other_state_path,socket_path,resolver_path,namespace=None):
    if not re.fullmatch(r'codi-net-[a-z0-9][a-z0-9-]{0,35}',instance) or role not in ('anonymous','registered') or any(not re.fullmatch(r'codi-[a-z0-9-]+',v) for v in (user,frontend_user)) or type(ping_gid) is not int or ping_gid<1:raise ValueError('Explicit managed unit identities required')
    for value in [release,python,settings_path,secret_path,state_path,other_state_path,socket_path,resolver_path]:path(str(value))
    policy_hash(settings_sha256)
    name=instance+'-'+role;service=name+'.service';sock=name+'.socket'
    def quote(value):return '"'+str(value)+'"'
    arguments=[str(python),'-I','-B',str(Path(release)/'scripts/serve-guest-wire.py'),'--settings',str(settings_path),'--settings-sha256',settings_sha256]
    common='[Unit]\nDescription=Codi fixed '+role+' guest wire\nRequires='+sock+'\nAfter='+sock+'\nStartLimitIntervalSec=60\nStartLimitBurst=5\n\n[Service]\nType=exec\nUser='+user+'\nGroup='+str(ping_gid)+'\n'
    values={'WorkingDirectory':str(release),'ExecStartPre':'+'+' '.join(map(quote,arguments+['--kernel-check'])),'ExecStart':' '.join(map(quote,arguments)),
        'LoadCredential':'wire.secret:'+str(secret_path),'Sockets':sock,'UMask':'0077','ProtectSystem':'strict','ProtectHome':'yes','PrivateTmp':'yes','PrivateDevices':'yes',
        'NoNewPrivileges':'yes','ProtectKernelTunables':'yes','ProtectKernelModules':'yes','ProtectControlGroups':'yes','RestrictSUIDSGID':'yes','RestrictNamespaces':'yes','LockPersonality':'yes',
        'RestrictAddressFamilies':'AF_UNIX AF_INET','CapabilityBoundingSet':'','AmbientCapabilities':'','ReadWritePaths':str(state_path),'BindReadOnlyPaths':str(resolver_path)+':/etc/resolv.conf',
        'InaccessiblePaths':str(other_state_path)+' -/etc/codi-connected -/var/lib/codi-connected -/etc/codi-user-files -/var/lib/codi-user-files -/etc/caddy -/var/lib/caddy',
        'MemoryMax':'256M','TasksMax':'64','LimitNOFILE':'256','LimitCORE':'0','Environment':'PYTHONDONTWRITEBYTECODE=1','Restart':'on-failure','RestartSec':'1s','TimeoutStopSec':'12s','KillMode':'control-group'}
    if namespace:
        if not re.fullmatch(r'/run/netns/codi-ng-fixture-[0-9a-f]{8}',namespace):raise ValueError('Explicit private fixture namespace required')
        values['NetworkNamespacePath']=namespace
    worker=(common+''.join(k+'='+v+'\n' for k,v in values.items())).encode()
    socket_unit=('[Unit]\nDescription=Codi protected '+role+' guest socket\n\n[Socket]\nListenStream='+str(socket_path)+'\nSocketUser='+frontend_user+'\nSocketGroup='+str(ping_gid)+'\nSocketMode=0600\nDirectoryMode=0755\nRemoveOnStop=yes\nAccept=no\nBacklog=16\nFileDescriptorName=wire\nService='+service+'\n').encode()
    return {service:worker,sock:socket_unit}
