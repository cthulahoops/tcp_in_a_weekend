import struct
from dataclasses import dataclass
import dataclasses

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

SOURCE_IP = "192.0.2.2"


@dataclass
class IPv4:
    vers_ihl: int
    tos: int
    total_length: int
    id: int
    frag_off: int
    ttl: int
    protocol: int
    checksum: int
    src: bytes  # an IP is 4 bytes
    dst: bytes

    @classmethod
    def packing_format(cls):
        return "!BBHHHBBH4s4s"


def ipv4_create(content_length: int, protocol: int, dest_ip: bytes, ttl=64) -> IPv4:
    ipv4 = IPv4(
        vers_ihl=4 << 4 | 5,
        tos=0,
        total_length=20 + content_length,
        id=1,
        frag_off=0,
        ttl=ttl,
        protocol=protocol,
        checksum=0,
        src=ip_to_bytes(SOURCE_IP),
        dst=ip_to_bytes(dest_ip),
    )
    ipv4.checksum = checksum(ipv4_to_bytes(ipv4))
    return ipv4


def ipv4_to_bytes(header: IPv4) -> bytes:
    fields = dataclasses.astuple(header)
    return struct.pack(header.packing_format(), *fields)


def ipv4_from_bytes(data: bytes) -> IPv4:
    fields = struct.unpack(IPv4.packing_format(), data)
    return IPv4(*fields)


def checksum(data: bytes) -> int:
    # add padding to make it an even number of bytes
    if len(data) % 2 == 1:
        data += b"\x00"
    fmt = "!" + "H" * (len(data) // 2)
    parts = struct.unpack(fmt, data)

    result = 0
    for part in parts:
        result += part
        # wrap to make the result between 0 and 2^16-1
        # This is a thing!

        # It is okay to do this outside the loop?
        result = (result >> 16) + (result & 0xFFFF)

    return ~result & 0xFFFF


def ip_to_bytes(ip: str) -> bytes:
    return bytes([int(x) for x in ip.split(".")])
