import pytest
from tiaw.ip import checksum, ipv4_create, PROTO_ICMP, ipv4_to_bytes, ipv4_from_bytes


@pytest.mark.parametrize(
    "hex_example, expected",
    [
        ("11aabbccddee123412341234", 7678),
        ("01", 0xFEFF),
        ("0001", 0xFFFE),
        ("00010001", 0xFFFD),
    ],
)
def test_checksum(hex_example, expected):
    data = bytes.fromhex(hex_example)
    assert checksum(bytes(data)) == expected


def test_packet():
    ipv4 = ipv4_create(
        content_length=5, protocol=PROTO_ICMP, dest_ip="192.0.2.2", ttl=64
    )
    encoded = ipv4_to_bytes(ipv4)
    decoded = ipv4_from_bytes(encoded)
    assert decoded == ipv4
