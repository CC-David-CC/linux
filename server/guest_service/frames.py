"""Bounded Ethernet policy shared by anonymous and registered guest workers."""
import ipaddress
import socket
from functools import partial

from .egress import OwnerEgressPolicy

GUEST=socket.inet_aton('10.86.0.2')
GATEWAY=socket.inet_aton('10.86.0.1')
DNS=socket.inet_aton('10.86.0.3')

def permitted(frame,policy,*,registered=False,scope=None):
    permits = partial(policy.permits, scope=scope) if isinstance(policy, OwnerEgressPolicy) else policy.permits
    if not isinstance(frame,bytes) or not 14<=len(frame)<=1518:return False
    kind=int.from_bytes(frame[12:14],'big')
    if kind==0x0806:
        return (len(frame)>=42 and frame[14:20]==b'\x00\x01\x08\x00\x06\x04'
                and frame[20:22] in (b'\x00\x01',b'\x00\x02')
                and frame[28:32]==GUEST and frame[38:42] in (GATEWAY,DNS))
    if kind!=0x0800 or len(frame)<34 or frame[14]!=0x45:return False
    total=int.from_bytes(frame[16:18],'big')
    if total<20 or len(frame)<14+total or int.from_bytes(frame[20:22],'big')&0xbfff or frame[26:30]!=GUEST:return False
    protocol=frame[23];destination=str(ipaddress.IPv4Address(frame[30:34]));payload=frame[34:14+total]
    if protocol==1:
        if len(payload)<8 or payload[:2]!=b'\x08\x00':return False
        name,port='icmp-echo',None
    elif protocol==6:
        if len(payload)<20 or not 20<=((payload[12]>>4)*4)<=len(payload):return False
        name,port='tcp',int.from_bytes(payload[2:4],'big')
    elif protocol==17:
        if len(payload)<8 or int.from_bytes(payload[4:6],'big')!=len(payload):return False
        # Virtual DNS is still Internet access: consult the verified worker role
        # before allowing QEMU to proxy a query to the fixed public resolvers.
        return (frame[30:34]==DNS and int.from_bytes(payload[2:4],'big')==53
                and permits(policy.dns_ipv4[0],'udp',53,registered=registered,dns_proxy=True))
    else:return False
    return permits(destination,name,port,registered=registered)
