from ctypes import Structure, c_uint32, c_uint16, c_ubyte
from ipaddress import ip_address
from scapy.layers.l2 import getmacbyip


def get_mac_addr_by_ip(ip: str):
    mac_addr = getmacbyip(ip)
    return [int(x, 16) for x in mac_addr.split(":")]


class SocketAddress:
    def from_address(self, ip: str, port: int):
        int_ip = int(ip_address(ip))
        self.ip = c_uint32(int_ip)
        self.port = c_uint16(port)
        self.mac_address = (c_ubyte * 6)(*get_mac_addr_by_ip(ip))


class VirtualIPArgs(Structure, SocketAddress):
    _fields_ = [
        ("ip", c_uint32),
        ("port", c_uint16),
        ("mac_address", c_ubyte * 6),
        ("num_reals", c_uint16),
    ]


class RealAddress(Structure, SocketAddress):
    _fields_ = [("ip", c_uint32), ("port", c_uint16), ("mac_address", c_ubyte * 6)]
