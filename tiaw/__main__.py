import struct
from fcntl import ioctl
from select import select
from . import icmp
from . import ip
from . import udp
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

    @property
    def elapsed_time(self):
        return self.end_time - self.start_time


@contextmanager
def timer():
    info = TimingInfo(start_time=time.time(), end_time=None)

    try:
        yield info
    finally:
        info.end_time = time.time()


def ping(tun, destination):
    for i in range(5):
        # create ping packet
        packet = icmp.add_ip_header(ip.PROTO_ICMP, destination, icmp.make_ping(seq=i))
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


def dns(tun):
    query = b"D\xcb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    udp_packet = udp.udp_create("8.8.8.8", 12345, 53, query)

    print(udp_packet.hex())

    print(udp.udp_from_bytes(udp_packet[20:]))

    tun.write(udp_packet)
    response = read_with_timeout(tun, 1024)

    ip.ipv4_from_bytes(response[:20])
    udp_response, contents = udp.udp_from_bytes(response[20:])

    print(udp_response)
    print(list(contents[-4:]))


if __name__ == "__main__":
    tun = open_tun("tun0")
    dns(tun)
    # ping(tun, "192.0.2.1")
    # ping(tun, "8.8.8.8")
