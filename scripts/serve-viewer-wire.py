#!/usr/bin/env python3
"""Run the dedicated, socket-activated WebOS guest worker or its firewall check."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'packages'))

from aiohttp import web
from guest_service.egress import OwnerEgressPolicy
from guest_service.installation import root_file, semantic_kernel
from guest_service.unix_transport import inherited_listener, peer_middleware
from guest_service.usage import Permissions, UsageLedger
from guest_service.worker import WireWorker

TABLE = 'webos_viewer_wire'
NFT = '/usr/sbin/nft'
CONFIG = Path('/etc/webos-guest-network')
RUN = Path('/run/webos-guest-network')
DATA = Path('/var/lib/webos-guest-network')


def command(argv, **options):
    return subprocess.run(argv, check=True, capture_output=True, timeout=10, **options).stdout


def inputs():
    settings = json.loads(root_file(CONFIG / 'worker.json'))
    profile = json.loads(root_file(CONFIG / 'active.json'))
    if set(settings) != {'frontendUser', 'issuer', 'qemuSHA256', 'policySHA256'}:
        raise ValueError('Unexpected installed guest worker configuration')
    if set(profile) != {'policy', 'workerSocket'} or profile['workerSocket'] != str(RUN / 'registered.sock'):
        raise ValueError('Unexpected guest socket configuration')
    policy = OwnerEgressPolicy.parse(profile['policy'])
    if policy.sha256 != settings['policySHA256']:
        raise ValueError('Guest configuration changed. Activate the matching worker policy first.')
    return settings, policy


def guard(*, install, monitor=False):
    settings, policy = inputs()
    uid = pwd.getpwnam('webos-guest-wire').pw_uid
    rules = policy.viewer_firewall(uid).encode()
    # Read back the expected native representation in a temporary network namespace.
    # No host rule is changed by calibration.
    expected = command(['/usr/bin/unshare', '--net', '/bin/sh', '-ec',
                        '/usr/sbin/nft -f -; /usr/sbin/nft -j list table inet webos_viewer_wire'], input=rules)
    witness = semantic_kernel(json.loads(expected), TABLE)
    listing = json.loads(command([NFT, '-j', 'list', 'tables']))
    exists = any(row.get('table', {}).get('family') == 'inet' and row['table']['name'] == TABLE
                 for row in listing['nftables'])
    if not exists and install:
        # Exclusive create and complete rules are one transaction.
        command([NFT, '-f', '-'], input=b'create table inet webos_viewer_wire\n' + rules)
    notify_socket = os.environ.get('NOTIFY_SOCKET') if monitor else None
    while True:
        actual = command([NFT, '-j', 'list', 'table', 'inet', TABLE])
        if semantic_kernel(json.loads(actual), TABLE) != witness:
            raise ValueError('Installed guest firewall differs from the verified policy')
        if notify_socket:
            address = '\0' + notify_socket[1:] if notify_socket.startswith('@') else notify_socket
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
                client.sendto(b'READY=1', address)
            notify_socket = None
        if not monitor:
            return
        time.sleep(1)


def serve():
    settings, policy = inputs()
    who = pwd.getpwnam('webos-guest-wire')
    front = pwd.getpwnam(settings['frontendUser'])
    state = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines())
    if (who.pw_uid == front.pw_uid or os.getuid() != who.pw_uid or os.geteuid() != who.pw_uid or
            int(state['CapEff'], 16) or state['NoNewPrivs'].strip() != '1'):
        raise ValueError('Dedicated unprivileged worker required')
    binary = root_file('/usr/bin/qemu-system-i386', mode=0o755, maximum=67108864)
    if hashlib.sha256(binary).hexdigest() != settings['qemuSHA256']:
        raise ValueError('Installed QEMU changed')
    if (os.environ.get('LISTEN_PID') != str(os.getpid()) or os.environ.get('LISTEN_FDS') != '1' or
            os.environ.get('LISTEN_FDNAMES') != 'wire'):
        raise ValueError('Expected the protected, inherited guest socket')
    listener = inherited_listener(3, str(RUN / 'registered.sock'), front.pw_uid, front.pw_gid)
    os.close(3)
    secret = (Path(os.environ['CREDENTIALS_DIRECTORY']) / 'webos-registered-wire').read_text('ascii')
    ledger = UsageLedger(DATA / 'usage.sqlite', 'registered', Permissions(CONFIG / 'permissions.sqlite'))
    issuer = settings['issuer']
    worker = WireWorker('registered', issuer['issuer'], policy, issuer, secret, usage=ledger)
    app = worker.app()
    app.middlewares.append(peer_middleware(front.pw_uid, front.pw_gid))
    web.run_app(app, sock=listener, access_log=None, print=None, shutdown_timeout=5)


if __name__ == '__main__':
    if sys.argv[1:] == ['guard']:
        guard(install=True, monitor=True)
    elif sys.argv[1:] == ['check']:
        guard(install=False)
    elif sys.argv[1:] == ['serve']:
        serve()
    else:
        sys.exit('Expected guard, check or serve')
