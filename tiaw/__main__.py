import struct
from fcntl import ioctl
import os
from select import select
from dataclasses import dataclass
import dataclasses
import struct


def open_tun(tunName):
    tun = open("/dev/net/tun", "r+b", buffering=0)
    LINUX_IFF_TUN = 0x0001
    LINUX_IFF_NO_PI = 0x1000
    LINUX_TUNSETIFF = 0x400454CA
    flags = LINUX_IFF_TUN | LINUX_IFF_NO_PI
    ifs = struct.pack("16sH22s", tunName, flags, b"")
    ioctl(tun, LINUX_TUNSETIFF, ifs)
    return tun


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


# timeout is in seconds
def read_with_timeout(tun, n_bytes, timeout=1.0):
    reads, _, _ = select([tun], [], [], timeout)
    if len(reads) == 0:
        raise TimeoutError("Timed out")
    return tun.read(n_bytes)


def ipv4_to_bytes(header: IPv4) -> bytes:
    fields = dataclasses.astuple(header)
    return struct.pack("!BBHHHBBH4s4s", *fields)


def ipv4_from_bytes(data: bytes) -> IPv4:
    fields = struct.unpack("!BBHHHBBH4s4s", data)
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
        result = (result >> 16) + (result & 0xFFFF)
    return ~result & 0xFFFF


packet = ipv4_to_bytes(
    IPv4(
        vers_ihl=4 << 4 | 5,
        tos=0,
        total_length=28,
        id=1,
        frag_off=0,
        ttl=16,
        protocol=6,
        checksum=0,
        src=bytes([192, 168, 0, 1]),
        dst=bytes([8, 8, 8, 8]),
    )
)

print(packet)

data = bytes.fromhex("11aabbccddee123412341234")
print(checksum(data))


# tun = open_tun(b"tun0")

# reply = read_with_timeout(tun, 1024)

# syn = b'E\x00\x00,\x00\x01\x00\x00@\x06\xf6\xc7\xc0\x00\x02\x02\xc0\x00\x02\x0109\x1f\x90\x00\x00\x00\x00\x00\x00\x00\x00`\x02\xff\xff\xc4Y\x00\x00\x02\x04\x05\xb4'
# tun.write(syn)
# reply = read_with_timeout(tun, 1024)
# print(repr(reply))
