"""Protected inherited Unix listener and native peer credentials for workers."""
import os
from pathlib import Path
import re
import socket
import stat
import struct
from aiohttp import web

def identity(value):
    if type(value) is not int or not 1<=value<=4294967294:raise ValueError('Explicit non-root service identity required')
    return value

def inherited_listener(fd,path,frontend_uid,ping_gid):
    identity(frontend_uid);identity(ping_gid)
    if type(fd) is not int or fd<3:raise ValueError('Explicit inherited listener descriptor required')
    if not isinstance(path,str) or not re.fullmatch(r'/[A-Za-z0-9_./-]+',path) or any(v in ('','.','..') for v in path.split('/')[1:]):raise ValueError('Canonical protected Unix socket path required')
    file=Path(path)
    for parent in file.parents:
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('Socket parents must be immutable root directories')
    info=file.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_nlink!=1 or info.st_uid!=frontend_uid or info.st_gid!=ping_gid or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError('Frontend-owned private Unix socket required')
    if not stat.S_ISSOCK(os.fstat(fd).st_mode):raise ValueError('Inherited descriptor must be a socket')
    duplicate=os.dup(fd)
    try:listener=socket.socket(fileno=duplicate)
    except BaseException:os.close(duplicate);raise
    try:
        if listener.family!=socket.AF_UNIX or listener.type!=socket.SOCK_STREAM or listener.getsockname()!=path or listener.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN)!=1:raise ValueError('Unexpected inherited worker listener')
        return listener
    except BaseException:listener.close();raise

def peer_middleware(frontend_uid,ping_gid):
    identity(frontend_uid);identity(ping_gid)
    @web.middleware
    async def guard(request,handler):
        stream=request.transport.get_extra_info('socket')
        if stream is None or stream.family!=socket.AF_UNIX:raise web.HTTPForbidden()
        pid,uid,gid=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if pid<=0 or not ((uid==frontend_uid and gid==ping_gid) or uid==0 and request.raw_path=='/healthz'):raise web.HTTPForbidden()
        return await handler(request)
    return guard
