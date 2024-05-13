from argparse import ArgumentParser
from address_types import RealAddress, VirtualIPArgs
from ctypes import c_uint32
from bcc import BPF


def build_parser():
    parser = ArgumentParser("pounder")
    parser.add_argument("vip", type=str, help="Virtual socket address to listen on")
    parser.add_argument(
        "reals", nargs="+", type=str, help="Real socket addresses to distribute load to"
    )
    return parser


def parse_socket_address(address: str):
    if ":" not in address:
        raise ValueError(f"Address {address} must be in form IP:PORT")
    ip, port = address.split(":")
    try:
        port = int(port)
    except ValueError:
        raise ValueError(f"Invalid port {port}, must be int")
    return ip, port


def main():
    parser = build_parser()
    args = parser.parse_args()
    vip_ip, vip_port = parse_socket_address(args.vip)
    vip_args_struct = VirtualIPArgs()
    vip_args_struct.from_address(vip_ip, vip_port)
    vip_args_struct.num_reals = len(args.reals)

    real_structs = []
    for real in args.reals:
        real_ip, real_port = parse_socket_address(real)
        real_struct = RealAddress()
        real_struct.from_address(real_ip, real_port)
        real_structs.append(real_struct)

    device = "lo"
    b = BPF(src_file="ebpf/xdp_entry.c")
    fn = b.load_func("xdp_entry", BPF.XDP)
    b.attach_xdp(device, fn, 0)
    try:
        arguments_map = b.get_table("arguments")
        reals_map = b.get_table("reals")
        arguments_map[c_uint32(0)] = vip_args_struct
        for i, real_struct in enumerate(real_structs):
            reals_map[c_uint32(i)] = real_struct
        b.trace_print()
    except KeyboardInterrupt:
        ...
    finally:
        b.remove_xdp(device, 0)


if __name__ == "__main__":
    main()
