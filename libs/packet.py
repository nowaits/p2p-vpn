import struct


class PacketHeader():
    data = 1
    control = 2
    heartbeat = 3
    heartbeat_ack = 4
    invalid_type = 5
    need_more_data = 6
    format = "!BH"
    format_size = struct.calcsize(format)


def packet_pack(p, t):
    return struct.pack(
        PacketHeader.format, t, len(p)
    ) + p


def packet_unpack(p):
    if len(p) < PacketHeader.format_size:
        return (PacketHeader.need_more_data, None, p)
    t, l = struct.unpack_from(PacketHeader.format, p)
    if t >= PacketHeader.invalid_type:
        return (PacketHeader.invalid_type, None, None)
    all_len = l + PacketHeader.format_size
    if all_len > len(p):
        return (PacketHeader.need_more_data, None, p)
    return (t, p[PacketHeader.format_size:all_len], p[all_len:])


def packet_unpack_all(data):
    ps = []
    while True:
        t, p, data = packet_unpack(data)
        if t < PacketHeader.invalid_type:
            ps.append((t, p))
        elif t == PacketHeader.invalid_type:
            return False, None, b''
        else:
            break

    return True, ps, data
