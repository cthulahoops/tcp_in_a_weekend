from dataclasses import dataclass
from . import packet
from . import ip


@dataclass
class ICMPEcho:
    type: packet.Byte
    code: packet.Byte
    checksum: packet.Int2
    id: packet.Int2
    seq: packet.Int2


def icmp_to_bytes(icmp):
    return packet.encode(icmp)


def icmp_from_bytes(string):
    return packet.decode(ICMPEcho, string)


def make_ping(seq=1):
    icmp = ICMPEcho(type=8, code=0, checksum=0, id=12345, seq=seq)
    icmp.checksum = packet.checksum(icmp_to_bytes(icmp))
    return icmp_to_bytes(icmp)


def add_ip_header(protocol, destination, data):
    ipv4 = ip.ipv4_create(content_length=len(data), protocol=protocol, dest_ip=destination)
    return ip.ipv4_to_bytes(ipv4) + data
