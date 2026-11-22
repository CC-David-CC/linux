"""Connect the WebOS Accounts service to the optional, protected guest worker."""
import json
import os
from pathlib import Path
import re
import secrets
import time

from aiohttp import web
from webos_accounts.guest_authority import AUTHORIZE, CHALLENGE, STATUS, GuestAuthority

from .authorization import NetworkDenied
from .coordinator import GuestCoordinator
from .egress import OwnerEgressPolicy
from .installation import root_file
from .runtime import metadata
from .usage import Permissions


class ViewerWire(GuestCoordinator):
    """Short-lived transport tickets. The worker independently verifies each account grant."""

    def __init__(self, origin, policy, endpoints):
        super().__init__(origin, policy, endpoints, secrets.token_urlsafe(32))
        self.tickets = {}

    def issue_cookie(self, response, secure):
        now = time.monotonic()
        self.tickets = {token: until for token, until in self.tickets.items() if until > now}
        if len(self.tickets) >= 256:
            raise web.HTTPTooManyRequests(headers={'Retry-After': '30'})
        token = secrets.token_urlsafe(32)
        self.tickets[token] = now + 30
        response.set_cookie('codi_guest_relay', token, max_age=30, secure=secure,
                            httponly=True, samesite='Strict', path=self.base_path + '/guest-network')

    def accepts_cookie(self, value):
        return self.tickets.get(value, 0) > time.monotonic()


class ViewerNetwork:
    def __init__(self, origin, policy_path, secret, *, socket_path='/run/webos-guest-network/registered.sock'):
        self.origin = origin
        self.path = Path(policy_path)
        self.permissions = Permissions(self.path.with_name('permissions.sqlite'))
        self.endpoint = {'registered': {'socket': socket_path, 'secret': secret}}
        self.wire = None

    @classmethod
    def installed(cls, origin, policy_path):
        folder = Path(os.environ['CREDENTIALS_DIRECTORY'])
        if not folder.is_absolute():
            raise ValueError('Expected the service credential directory')
        secret = (folder / 'webos-registered-wire').read_text('ascii')
        if not re.fullmatch(r'[A-Za-z0-9_-]{43,128}', secret):
            raise ValueError('Invalid installed guest wire credential')
        return cls(origin, policy_path, secret)

    def policy(self):
        try:
            return OwnerEgressPolicy.parse(json.loads(root_file(self.path, maximum=8192)))
        except (ValueError, OSError):
            return None

    def configure(self, config):
        policy = self.policy()
        if policy is not None:
            config['guestNetwork'] = {**metadata('', policy.sha256), 'previewPolicy': policy.public_preview(),
                                      'relayAdmission': 'signed-status-cookie'}

    def authority(self, accounts, application):
        def dispatch(env, start):
            if env.get('PATH_INFO') not in (CHALLENGE, STATUS, AUTHORIZE):
                return application(env, start)
            policy = self.policy()
            if policy is None:
                return accounts.json_response(start, 403, {'error': 'Guest networking is unavailable'})
            def allowed(subject, now):
                scope = policy.scope(subject, now)
                if scope is None:
                    return None
                try:
                    self.permissions.policy('registered', subject)
                except (NetworkDenied, ValueError, OSError):
                    return None
                return policy.test_end if scope == 'test' else now + 30
            authority = GuestAuthority(accounts, policy_sha256=policy.sha256, allowed_until=allowed,
                                       application=application)
            return authority(env, start)
        return dispatch

    def current_wire(self):
        policy = self.policy()
        if policy is None:
            raise web.HTTPForbidden()
        if self.wire is None or self.wire.policy != policy:
            self.wire = ViewerWire(self.origin, policy, self.endpoint)
        return self.wire

    def account_response(self, request, response):
        if request.method == 'POST' and request.path == STATUS and response.status == 200:
            wire = self.current_wire()
            if json.loads(response.body)['policy_sha256'] != wire.policy.sha256:
                raise web.HTTPConflict(text='Guest network policy changed')
            wire.issue_cookie(response, self.origin.startswith('https://'))

    async def relay(self, request):
        return await self.current_wire().relay(request)
