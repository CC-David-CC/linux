"""One operator policy for packet decisions and scoped native socket rules.

IPv4 special-use destinations are deliberately stricter than is_global (the
192.0.0/24 anycast exceptions are denied too). This explicit set gives Python
and nftables identical semantics across Python classification changes. See the
IANA IPv4 Special-Purpose Address Registry; multicast is denied independently.
"""
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import uuid

DENY_IPV4=('0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16',
           '172.16.0.0/12','192.0.0.0/24','192.0.2.0/24','192.88.99.0/24','192.168.0.0/16',
           '198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','224.0.0.0/4','240.0.0.0/4')
NETWORKS=tuple(ipaddress.IPv4Network(v) for v in DENY_IPV4)
OWNER_POLICY_VERSION = 'codi-guest-egress-policy/3'
LAN_NETWORKS = tuple(ipaddress.IPv4Network(value) for value in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))

def public_ipv4(value):
    if not isinstance(value,str):raise ValueError('Canonical IPv4 required')
    address=ipaddress.IPv4Address(value)
    if str(address)!=value or any(address in net for net in NETWORKS):raise ValueError('Unicast public IPv4 required')
    return value

def number(value,minimum,maximum):
    if type(value) is not int or not minimum<=value<=maximum:raise ValueError('Bounded operator integer required')
    return value

@dataclass(frozen=True)
class EgressPolicy:
    own_public_ipv4:tuple
    dns_ipv4:tuple

    def __post_init__(self):
        for values,maximum in [(self.own_public_ipv4,8),(self.dns_ipv4,4)]:
            if type(values) is not tuple or not 1<=len(values)<=maximum:raise ValueError('Explicit bounded address tuple required')
            for address in values:public_ipv4(address)
            if len(set(values))!=len(values):raise ValueError('Unique operator addresses required')
        if set(self.own_public_ipv4)&set(self.dns_ipv4):raise ValueError('DNS must not bypass protected own-address policy')

    @classmethod
    def parse(cls,value):
        if not isinstance(value,dict) or set(value)!={'version','ownPublicIPv4','dnsIPv4'} or value['version']!='codi-guest-egress-policy/1':raise ValueError('Exact guest egress policy required')
        if any(not isinstance(value[k],list) for k in ['ownPublicIPv4','dnsIPv4']):raise ValueError('Address arrays required')
        return cls(tuple(value['ownPublicIPv4']),tuple(value['dnsIPv4']))

    def value(self):
        return {'version':'codi-guest-egress-policy/1','ownPublicIPv4':list(self.own_public_ipv4),'dnsIPv4':list(self.dns_ipv4)}

    def effective_value(self):
        return {**self.value(),'deniedIPv4':list(DENY_IPV4),'tcpPorts':[80,443],
                'icmp':'echo-request-code0','ipv6':'deny','anonymousOwnAddress':'deny',
                'virtualWire':{'sourceIPv4':'10.86.0.2','gatewayIPv4':'10.86.0.1','dnsIPv4':'10.86.0.3','arpOperations':[1,2],'dns':'udp53'}}

    @property
    def sha256(self):
        return hashlib.sha256(json.dumps(self.effective_value(),sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def permits(self,destination,protocol,port=None,*,registered=False,dns_proxy=False):
        if type(registered) is not bool or type(dns_proxy) is not bool:raise ValueError('Trusted role and DNS-proxy decisions required')
        try:public_ipv4(destination)
        except (ValueError,TypeError):return False
        if destination in self.own_public_ipv4 and not registered:return False
        if dns_proxy:return destination in self.dns_ipv4 and protocol in ('udp','tcp') and type(port) is int and port==53
        return protocol=='icmp-echo' and port is None or protocol=='tcp' and type(port) is int and port in (80,443)

    def nftables(self,*,anonymous_uid,registered_uid,frontend_uid,anonymous_port=8141,registered_port=8142,frontend_port=8132,issuer_port=8118,unix_workers=False):
        if type(unix_workers) is not bool:raise ValueError('Explicit internal transport policy required')
        uids=[number(v,1,4294967294) for v in [anonymous_uid,registered_uid,frontend_uid]]
        if len(set(uids))!=3:raise ValueError('Separate network role UIDs required')
        ports=[number(v,1024,65535) for v in [anonymous_port,registered_port,frontend_port,issuer_port]]
        if len(set(ports))!=4:raise ValueError('Distinct fixed loopback service ports required')
        deny=', '.join(DENY_IPV4);own=', '.join(self.own_public_ipv4);dns=', '.join(self.dns_ipv4)
        lines=['table inet codi_guest_egress {',f' set private4 {{ type ipv4_addr; flags interval; elements = {{ {deny} }} }}',
               f' set own4 {{ type ipv4_addr; elements = {{ {own} }} }}',f' set dns4 {{ type ipv4_addr; elements = {{ {dns} }} }}',
               ' chain output {','  type filter hook output priority filter; policy accept;',
               f'  meta skuid {anonymous_uid} jump anonymous',f'  meta skuid {registered_uid} jump registered',f'  meta skuid {frontend_uid} jump frontend',' }']
        # Reply-only loopback exceptions keep fixed worker/control servers usable
        # without letting their UID initiate arbitrary host-service connections.
        def reply(port):return f'  ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport {port} ct direction reply ct state established counter accept'
        for name,port in [('anonymous',anonymous_port),('registered',registered_port)]:
            lines += [' chain '+name+' {',*([reply(port)] if not unix_workers else []),'  ip daddr @private4 counter reject with icmpx type admin-prohibited']
            if name=='anonymous':lines+=['  ip daddr @own4 counter reject with icmpx type admin-prohibited']
            lines += ['  ip daddr @dns4 udp dport 53 counter accept','  ip daddr @dns4 tcp dport 53 counter accept',
                      '  ip protocol icmp icmp type echo-request icmp code 0 counter accept',
                      '  meta nfproto ipv4 tcp dport { 80, 443 } counter accept',
                      '  counter reject with icmpx type admin-prohibited',' }']
        control_ports=str(issuer_port) if unix_workers else ', '.join(map(str,[issuer_port,anonymous_port,registered_port]))
        lines += [' chain frontend {',reply(frontend_port),f'  ip daddr 127.0.0.1 tcp dport {{ {control_ports} }} counter accept',
                  '  counter reject with icmpx type admin-prohibited',' }','}']
        return '\n'.join(lines)+'\n'


def account_subject(value):
    """Validate the immutable subject issued by the account service."""
    if not isinstance(value, str) or not value.startswith('user:'):
        raise ValueError('A registered account subject is required')
    if value != f'user:{uuid.UUID(value[5:])}':
        raise ValueError('The account subject must be canonical')
    return value


@dataclass(frozen=True)
class OwnerEgressPolicy(EgressPolicy):
    """Owner Internet access and one configured LAN SSH destination."""

    owner: str | None
    ssh_host: str
    test_subject: str | None = None
    test_start: int | None = None
    test_end: int | None = None

    def __post_init__(self):
        super().__post_init__()
        if self.owner is not None:
            account_subject(self.owner)
        elif self.test_subject is None:
            raise ValueError('A test-only policy requires a bounded test account')
        host = ipaddress.IPv4Address(self.ssh_host)
        if str(host) != self.ssh_host or not any(host in network for network in LAN_NETWORKS):
            raise ValueError('The SSH destination must be a fixed LAN IPv4 address')
        if host in ipaddress.IPv4Network('10.86.0.0/24'):
            raise ValueError('The SSH destination overlaps the virtual guest network')
        if self.test_subject is None:
            if self.test_start is not None or self.test_end is not None:
                raise ValueError('A test window requires a test account subject')
            return
        if account_subject(self.test_subject) == self.owner:
            raise ValueError('The test account must differ from the owner')
        start = number(self.test_start, 1, 2**63 - 1)
        end = number(self.test_end, 1, 2**63 - 1)
        if not 0 < end - start <= 3600:
            raise ValueError('The test window must end within one hour of activation')

    @classmethod
    def parse(cls, value):
        fields = {'version', 'ownPublicIPv4', 'dnsIPv4', 'ownerSubject', 'sshHost', 'test'}
        if not isinstance(value, dict) or set(value) != fields or value['version'] != OWNER_POLICY_VERSION:
            raise ValueError('Exact owner guest policy required')
        if not all(isinstance(value[key], list) for key in ('ownPublicIPv4', 'dnsIPv4')):
            raise ValueError('Address arrays required')
        test = value['test']
        if test is None:
            parts = (None, None, None)
        elif isinstance(test, dict) and set(test) == {'subject', 'start', 'end'}:
            if test['subject'] is None:
                raise ValueError('A test window requires a registered account subject')
            parts = (test['subject'], test['start'], test['end'])
        else:
            raise ValueError('Exact temporary test account required')
        return cls(tuple(value['ownPublicIPv4']), tuple(value['dnsIPv4']), value['ownerSubject'], value['sshHost'], *parts)

    def value(self):
        test = None if self.test_subject is None else {'subject': self.test_subject, 'start': self.test_start, 'end': self.test_end}
        return {**super().value(), 'version': OWNER_POLICY_VERSION, 'ownerSubject': self.owner, 'sshHost': self.ssh_host, 'test': test}

    def public_preview(self):
        return {'version': OWNER_POLICY_VERSION, 'externalNetwork': 'owner-only' if self.owner else 'scoped-test-only', 'anonymousInternet': 'deny'}

    def scope(self, subject, now):
        if self.owner is not None and subject == self.owner:
            return 'owner'
        if self.test_subject is not None and subject == self.test_subject and self.test_start <= now < self.test_end:
            return 'test'
        return None

    def permits(self, destination, protocol, port=None, *, registered=False, dns_proxy=False, scope=None):
        if type(registered) is not bool or type(dns_proxy) is not bool:
            raise ValueError('Trusted role and DNS-proxy decisions required')
        if not registered or scope not in ('owner', 'test') or (scope == 'owner' and self.owner is None):
            return False
        if not dns_proxy and destination == self.ssh_host and protocol == 'tcp' and type(port) is int and port == 22:
            return True
        return scope == 'owner' and super().permits(destination, protocol, port, registered=True, dns_proxy=dns_proxy)

    def nftables(self, **kwargs):
        generated = super().nftables(**kwargs)
        prefix, marker, tail = generated.partition(' chain anonymous {\n')
        body, end, rest = tail.partition('\n }\n')
        if not marker or not end or not rest.startswith(' chain registered {\n'):
            raise ValueError('Unexpected guest firewall layout')
        replies = [line for line in body.splitlines() if 'ct direction reply ct state established counter accept' in line]
        if len(replies) != (0 if kwargs.get('unix_workers', False) else 1):
            raise ValueError('Unexpected anonymous loopback rules')
        reject = '  counter reject with icmpx type admin-prohibited'
        private = '  ip daddr @private4 counter reject with icmpx type admin-prohibited'
        ssh = f'  ip daddr {self.ssh_host} tcp dport 22 counter accept'
        if rest.count(private) != 1:
            raise ValueError('Unexpected registered LAN filter')
        if self.owner is None:
            registered, close, frontend = rest.partition('\n }\n chain frontend {\n')
            if not close:
                raise ValueError('Unexpected registered firewall layout')
            control = [line for line in registered.splitlines() if 'ct direction reply ct state established counter accept' in line]
            rest = '\n'.join([' chain registered {', *control, ssh, reject]) + close + frontend
        else:
            rest = rest.replace(private, ssh + '\n' + private, 1)
        return prefix + marker + '\n'.join([*replies, reject]) + end + rest


def parse_runtime_policy(value):
    if isinstance(value, dict) and value.get('version') == OWNER_POLICY_VERSION:
        return OwnerEgressPolicy.parse(value)
    return EgressPolicy.parse(value)
