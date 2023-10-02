import dataclasses
import struct
import typing


class Byte(int):
    packing = "B"


class Int2(int):
    packing = "H"


class IpAddress(bytes):
    packing = "4s"


def packing_format(cls):
    return "!" + "".join(field.packing for field in typing.get_type_hints(cls).values())


def encode(data):
    fields = dataclasses.astuple(data)
    return struct.pack(packing_format(data), *fields)


def decode(cls, data):
    fields = struct.unpack(packing_format(cls), data)
    return cls(*fields)


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
