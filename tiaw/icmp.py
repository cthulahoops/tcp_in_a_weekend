from dataclasses import dataclass
import dataclasses
import struct
from . import ip


@dataclass
class ICMPEcho:
    type: int
    code: int
    checksum: int
    id: int
    seq: int


def icmp_to_bytes(icmp):
    fields = dataclasses.astuple(icmp)
    return struct.pack("!BBHHH", *fields)


def icmp_from_bytes(string):
    fields = struct.unpack("!BBHHH", string)
    return ICMPEcho(*fields)


def make_ping(seq=1):
    icmp = ICMPEcho(type=8, code=0, checksum=0, id=12345, seq=seq)
    icmp.checksum = ip.checksum(icmp_to_bytes(icmp))
    return icmp_to_bytes(icmp)


def add_ip_header(data):
    ipv4 = ip.ipv4_create(
        content_length=len(data), protocol=ip.PROTO_ICMP, dest_ip="192.0.2.1"
    )
    return ip.ipv4_to_bytes(ipv4) + data
