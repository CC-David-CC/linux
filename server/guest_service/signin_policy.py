"""Version 2 guest policy: every external socket requires registered identity.

The immutable version 1 parser/rules stay unchanged for old artifacts. Merely
importing this module does not alter an installed policy or any kernel rules.
"""
from dataclasses import dataclass
from .egress import EgressPolicy

VERSION='codi-guest-egress-policy/2'

@dataclass(frozen=True)
class SigninPolicy(EgressPolicy):
    @classmethod
    def parse(cls,value):
        if not isinstance(value,dict) or set(value)!={'version','ownPublicIPv4','dnsIPv4','anonymousInternet'} or value['version']!=VERSION or value['anonymousInternet']!='deny':
            raise ValueError('Exact registered-only guest policy required')
        if any(not isinstance(value[k],list) for k in ['ownPublicIPv4','dnsIPv4']):
            raise ValueError('Address arrays required')
        return cls(tuple(value['ownPublicIPv4']),tuple(value['dnsIPv4']))

    def value(self):
        return {**super().value(),'version':VERSION,'anonymousInternet':'deny'}

    def permits(self,destination,protocol,port=None,*,registered=False,dns_proxy=False):
        if type(registered) is not bool or type(dns_proxy) is not bool:
            raise ValueError('Trusted role and DNS-proxy decisions required')
        if not registered:return False
        return super().permits(destination,protocol,port,registered=True,dns_proxy=dns_proxy)

    def nftables(self,**kwargs):
        # Reuse the frozen generator/validation for registered/frontend roles.
        # The only replacement is the anonymous chain, with reply-only internal
        # TCP control when explicitly using the older TCP-worker fixture.
        generated=super().nftables(**kwargs)
        prefix,marker,remainder=generated.partition(' chain anonymous {\n')
        body,end,suffix=remainder.partition('\n }\n')
        if not marker or not end or not suffix.startswith(' chain registered {\n'):
            raise ValueError('Unexpected frozen kernel policy layout')
        replies=[line for line in body.splitlines() if 'ct direction reply ct state established counter accept' in line]
        if len(replies)!=(0 if kwargs.get('unix_workers',False) else 1):
            raise ValueError('Unexpected anonymous control reply rules')
        return prefix+marker+'\n'.join([*replies,'  counter reject with icmpx type admin-prohibited'])+end+suffix

def parse_policy(value):
    if isinstance(value,dict) and value.get('version')=='codi-guest-egress-policy/1':
        return EgressPolicy.parse(value)
    return SigninPolicy.parse(value)
