from dataclasses import dataclass
from . import packet
from . import ip


@dataclass
class UDPHeader:
    src_port: packet.Int2
    dst_port: packet.Int2
    length: packet.Int2
    checksum: packet.Int2


@dataclass
class PseudoHeader:
    src_ip: packet.IpAddress
    dst_ip: packet.IpAddress
    zero: packet.Byte
    protocol: packet.Byte
    length: packet.Int2


def udp_create(destination, src_port, dst_port, contents):
    udp_header = UDPHeader(
        src_port,
        dst_port,
        length=len(contents) + 8,
        checksum=0,
    )
    udp_bytes = udp_to_bytes(udp_header, contents)
    ipv4 = ip.ipv4_create(len(udp_bytes), ip.PROTO_UDP, destination)
    udp_header.checksum = pseudoheader_checksum(ipv4, udp_bytes)
    print(udp_header.checksum)
    return ip.ipv4_to_bytes(ipv4) + udp_to_bytes(udp_header, contents)


def pseudoheader_checksum(ipv4: ip.IPv4, contents: bytes) -> packet.Int2:
    pseudo_header = ipv4_to_pseudoheader(ipv4)
    return packet.checksum(packet.encode(pseudo_header) + contents)


def ipv4_to_pseudoheader(ipv4: ip.IPv4) -> PseudoHeader:
    return PseudoHeader(
        src_ip=ipv4.src,
        dst_ip=ipv4.dst,
        zero=0,
        protocol=ipv4.protocol,
        length=ipv4.total_length - 20,
    )


def udp_from_bytes(data: bytes) -> (UDPHeader, bytes):
    header, contents = data[:8], data[8:]
    return packet.decode(UDPHeader, header), contents


def udp_to_bytes(header: UDPHeader, contents: bytes) -> bytes:
    return packet.encode(header) + contents
