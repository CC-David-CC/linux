"""Public pinned frontend descriptor and private systemd wire credentials."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .authorization import context,policy_hash,WireAuthorization
from .egress import EgressPolicy

VERSION='codi-guest-frontend/1'
def metadata(base,policy_sha256):
    policy_hash(policy_sha256)
    return {'relayPath':base+'/guest-network','authorization':{'version':'codi-guest-network-auth/1','policySHA256':policy_sha256,'clientPath':base+'/guest-access/client.mjs'}}

def validate(value):
    fields={'version','origin','basePath','policy','policySHA256','issuerPolicy','frontendUID','frontendGID','workerSockets','guardUnit'}
    if not isinstance(value,dict) or set(value)!=fields or value['version']!=VERSION:raise ValueError('Exact guest frontend descriptor required')
    context(value['origin'],value['basePath'])
    policy=EgressPolicy.parse(value['policy'])
    if policy.sha256!=value['policySHA256']:raise ValueError('Frontend egress policy pin changed')
    WireAuthorization(value['issuerPolicy'],policy.sha256,base_path=value['basePath'])
    issuer=value['issuerPolicy']
    if set(issuer)!={'mode','apiBase','issuer','audience','authorityClass','authorityKeys'} or issuer.get('issuer')!=value['origin'] or issuer.get('apiBase')!=value['basePath']+'/api/v1' or issuer.get('authorityClass')!='development' or issuer.get('audience')!='codiserver-peers-v1':raise ValueError('Frontend issuer context changed')
    for entry in issuer['authorityKeys']:
        if set(entry)!={'kid','jwk'} or set(entry['jwk'])!={'kty','crv','x','y'}:raise ValueError('Only public issuer keys may enter frontend settings')
    for field in ['frontendUID','frontendGID']:
        if type(value[field]) is not int or not 1<=value[field]<=4294967294:raise ValueError('Explicit unprivileged frontend identity required')
    if not isinstance(value['guardUnit'],str) or not re.fullmatch(r'codi-net-[a-z0-9-]{1,40}-guard\.service',value['guardUnit']):raise ValueError('Fixed guest guard unit required')
    sockets=value['workerSockets']
    if not isinstance(sockets,dict) or set(sockets)!={'anonymous','registered'}:raise ValueError('Two distinct fixed Unix workers required')
    for path in sockets.values():
        if not isinstance(path,str) or not re.fullmatch(r'/[A-Za-z0-9_./-]+',path) or any(p in ('','.','..') for p in path.split('/')[1:]):raise ValueError('Canonical fixed worker socket required')
    if len(set(sockets.values()))!=2:raise ValueError('Two distinct fixed Unix workers required')
    return policy

def load(file,pin):
    file=Path(file)
    if not file.is_absolute() or '..' in file.parts:raise ValueError('Absolute protected frontend descriptor required')
    for part in [file,*file.parents]:
        info=part.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid or info.st_mode&0o022:raise ValueError('Immutable root frontend input required')
    with os.fdopen(os.open(file,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o644 or info.st_size>32768:raise ValueError('Bounded public frontend descriptor required')
        raw=stream.read(32769)
    if hashlib.sha256(raw).hexdigest()!=policy_hash(pin):raise ValueError('Frontend descriptor pin changed')
    value=json.loads(raw);validate(value)
    if os.getuid()!=value['frontendUID'] or os.getgid()!=value['frontendGID']:raise ValueError('Managed frontend identity changed')
    status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines())
    if int(status['CapEff'],16) or status['NoNewPrivs'].strip()!='1':raise ValueError('Unprivileged protected frontend required')
    parent='/run/codi-network/'+value['guardUnit'].removesuffix('-guard.service')+'/'
    for role,path in value['workerSockets'].items():
        if path!=parent+role+'.sock':raise ValueError('Root-reserved worker socket path changed')
        for folder in Path(path).parents:
            info=folder.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid or info.st_mode&0o022:raise ValueError('Immutable worker socket ancestors required')
        info=Path(path).lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_nlink!=1 or info.st_uid!=value['frontendUID'] or info.st_gid!=value['frontendGID'] or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError('Protected frontend worker socket required')
    return value

def credential(name):
    if name not in ('anonymous-wire.secret','registered-wire.secret'):raise ValueError('Explicit wire credential name required')
    folder=Path(os.environ.get('CREDENTIALS_DIRECTORY',''))
    if not re.fullmatch(r'/run/credentials/codi-[a-z0-9-]+-guest\.service',str(folder)):raise ValueError('Managed guest credential directory required')
    for parent in folder.parents:
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid or info.st_mode&0o022:raise ValueError('Protected credential ancestors required')
    directory=folder.lstat();file=folder/name
    with os.fdopen(os.open(file,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISDIR(directory.st_mode) or directory.st_uid!=0 or directory.st_gid!=0 or stat.S_IMODE(directory.st_mode)!=0o550 or not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o440 or not os.statvfs(file).f_flag&os.ST_RDONLY:raise ValueError('Read-only managed guest credential required')
        raw=stream.read(129)
    if not re.fullmatch(rb'[A-Za-z0-9_-]{43,128}',raw):raise ValueError('Bounded private wire credential required')
    return raw.decode('ascii')
