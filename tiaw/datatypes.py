class Byte(int):
    packing = "B"


class Int2(int):
    packing = "H"


class IpAddress(bytes):
    packing = "4s"
