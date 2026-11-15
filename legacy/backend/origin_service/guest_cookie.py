"""Persistent guest connection cookie, separate from identity and visitor files."""
import os
from pathlib import Path
import re
import secrets
import stat


def source(config):
    return Path(config['stateRoot']).parent / ('guest-cookie-' + config['instance']) / 'secret'


def validate_source(op, config):
    file = op.path(source(config))
    if stat.S_IMODE(file.parent.stat().st_mode) != 0o700:
        raise ValueError('Guest cookie directory must be root-private')
    raw = op.read_owned(file, 0, 0o600, 128)
    if not re.fullmatch(rb'[A-Za-z0-9_-]{43,128}', raw):
        raise ValueError('Invalid guest cookie token')
    return raw


def provision(op, config):
    # Called only for a new managed instance. Existing missing credentials
    # are an error; normal startup never silently generates a replacement.
    file = source(config)
    op.path(file.parent.parent)
    op.directory(file.parent, 0o700)
    if not file.exists():
        op.atomic(file, secrets.token_urlsafe(32).encode())
    validate_source(op, config)


def load(file, public_root):
    file = Path(file).absolute()
    for part in [file, *file.parents]:
        if part.is_symlink():
            raise ValueError('Guest cookie cannot use linked paths')
    if file.resolve().is_relative_to(Path(public_root).resolve()):
        raise ValueError('Guest cookie must be outside public assets')
    directory = file.parent.stat()
    with os.fdopen(os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        private = directory.st_uid == info.st_uid == os.getuid() and not (directory.st_mode | info.st_mode) & 0o077
        credential = (str(file.parent) == os.environ.get('CREDENTIALS_DIRECTORY') and
                      re.fullmatch(r'/run/credentials/codi-[a-z0-9-]+\.service/guest-cookie\.secret', str(file)) is not None and
                      directory.st_uid == directory.st_gid == info.st_uid == info.st_gid == 0 and
                      stat.S_IMODE(directory.st_mode) == 0o550 and stat.S_IMODE(info.st_mode) == 0o440 and
                      bool(os.statvfs(file).f_flag & os.ST_RDONLY) and
                      all(p.stat().st_uid == 0 and not p.stat().st_mode & 0o022 for p in file.parent.parents))
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 43 <= info.st_size <= 128 or not (private or credential):
            raise ValueError('Protected guest cookie file required')
        raw = stream.read(129)
    if not re.fullmatch(rb'[A-Za-z0-9_-]{43,128}', raw):
        raise ValueError('Invalid guest cookie token')
    return raw.decode('ascii')
