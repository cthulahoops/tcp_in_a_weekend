import struct
from fcntl import ioctl
from select import select
from .icmp import make_ping, add_ip_header
from . import ip


def open_tun(tun_name):
    tun = open("/dev/net/tun", "r+b", buffering=0)
    LINUX_IFF_TUN = 0x0001
    LINUX_IFF_NO_PI = 0x1000
    LINUX_TUNSETIFF = 0x400454CA
    flags = LINUX_IFF_TUN | LINUX_IFF_NO_PI
    ifs = struct.pack("16sH22s", tun_name.encode("utf-8"), flags, b"")
    ioctl(tun, LINUX_TUNSETIFF, ifs)
    return tun


# timeout is in seconds
def read_with_timeout(tun, n_bytes, timeout=1.0):
    reads, _, _ = select([tun], [], [], timeout)
    if len(reads) == 0:
        raise TimeoutError("Timed out")
    return tun.read(n_bytes)


tun = open_tun("tun0")
packet = add_ip_header(make_ping())
tun.write(packet)
reply = tun.read(1024)
print(repr(reply))
ipv4 = ip.ipv4_from_bytes(reply[:20])
print(ipv4)
