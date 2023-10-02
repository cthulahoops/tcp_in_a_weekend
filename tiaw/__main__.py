import struct
from fcntl import ioctl
from select import select
from . import icmp
from . import ip
import time
from contextlib import contextmanager
from dataclasses import dataclass


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


@dataclass
class TimingInfo:
    start_time: float
    end_time: float

    def elapsed_time(self):
        return self.end_time - self.start_time


@contextmanager
def timer():
    info = TimingInfo(start_time=time.time(), end_time=None)

    try:
        yield info
    finally:
        info.end_time = time.time()


def ping(destination):
    for i in range(5):
        # create ping packet
        packet = icmp.add_ip_header(icmp.make_ping(seq=i))
        # time how long it takes to get a reply
        with timer() as timing_info:
            tun.write(packet)
            reply = tun.read(1024)

        elapsed = round(timing_info.elapsed_time * 1000, 3)
        ipv4 = ip.ipv4_from_bytes(reply[:20])
        response = icmp.icmp_from_bytes(reply[20:])
        print(
            f"response from {destination}: icmp_seq={response.seq} ttl={ipv4.ttl} time={elapsed} ms"
        )


tun = open_tun("tun0")
ping("192.0.2.2")
