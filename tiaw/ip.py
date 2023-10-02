from dataclasses import dataclass
from . import packet

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17

SOURCE_IP = "192.0.2.2"


@dataclass
class IPv4:
    vers_ihl: packet.Byte
    tos: packet.Byte
    total_length: packet.Int2
    id: packet.Int2
    frag_off: packet.Int2
    ttl: packet.Byte
    protocol: packet.Byte
    checksum: packet.Int2
    src: packet.IpAddress
    dst: packet.IpAddress


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
    ipv4.checksum = packet.checksum(ipv4_to_bytes(ipv4))
    return ipv4


def ipv4_to_bytes(header: IPv4) -> bytes:
    return packet.encode(header)


def ipv4_from_bytes(data: bytes) -> IPv4:
    return packet.decode(IPv4, data)


def ip_to_bytes(ip: str) -> packet.IpAddress:
    return bytes([int(x) for x in ip.split(".")])
