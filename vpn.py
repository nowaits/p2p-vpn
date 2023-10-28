import sys
import socket
import select
from libs.tuntap import *
import utils
import time
import signal
import random
# from scapy.all import *
import threading
import queue

import argparse
import logging


def signal_handler(signal, frame):
    logging.info('Exit!')
    sys.exit(1)


LOG_LEVELS = (
    logging.NOTSET, logging.DEBUG,
    logging.INFO, logging.WARNING,
    logging.ERROR, logging.CRITICAL)
LOG_CHOICES = list(map(lambda x: logging.getLevelName(x), LOG_LEVELS))


def set_loggint_format(level):
    debug_info = " %(filename)s %(funcName)s:%(lineno)d "

    logging.basicConfig(
        level=level,
        stream=sys.stdout,
        format='[%(asctime)s %(levelname)s' + debug_info + ']: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def parse_args():
    def str2bool(str):
        return True if str.lower() == 'true' else False

    parser = argparse.ArgumentParser(description="vpn")

    parser.add_argument(
        "--client", "-c", action='store_true', help="client mode")
    parser.add_argument(
        "--show-status", default="true", type=str2bool, help="show status")
    parser.add_argument(
        "--cs-vpn", action='store_true', help="set for local vpn")
    parser.add_argument(
        "--server", "-s", type=str, default="192.168.20.1", help="server IP")
    parser.add_argument(
        "--port", "-p", type=int, default=4593,
        help="server port, default 4593")
    parser.add_argument(
        "--port-range", "-r", type=int, default=100, help="port range")
    parser.add_argument(
        "--vip", type=str, default="10.0.0.1",
        help="virtual ip, default 10.0.0.1")
    parser.add_argument(
        "--vmask", type=str, default="255.255.255.0",
        help="virtual ip mask, default 255.255.255.0")
    parser.add_argument("--token", "-t", type=str, help="user token")
    parser.add_argument(
        "--run-as-service", action='store_true', help="run as vpn service")
    parser.add_argument(
        '--verbose', default=LOG_CHOICES[2],
        choices=LOG_CHOICES, help="log level default:%s" % (LOG_CHOICES[2]))

    return parser.parse_args()


class PacketHeader():
    data = 1
    control = 2
    heartbeat = 3
    invalid_type = 4
    invalid_len = 5
    format = "!BH"
    format_size = struct.calcsize(format)


def vpn_packet_pack(p, t):
    return struct.pack(
        PacketHeader.format, t, len(p)
    ) + p


def vpn_packet_unpack(p):
    t, l = struct.unpack_from(PacketHeader.format, p)
    if t >= PacketHeader.invalid_type:
        return (PacketHeader.invalid_type, None)
    if l + PacketHeader.format_size != len(p):
        return (PacketHeader.invalid_len, None)
    return (t, p[PacketHeader.format_size:])


class VPN(object):

    def __init__(self, is_server, tun, need_negotiate, sock, show_status):
        self._is_server = is_server
        self._need_negotiate = need_negotiate
        self._tun = TunTap(nic_type="Tun", nic_name="tun0")
        self._tun.config(tun[0], tun[1], mtu=tun[2])
        assert sock != None
        self._sock = sock
        self._peer = None
        self._terminate = False
        self._show_status = show_status
        self._tun.mtu = tun[2]
        self._tun_read_queue = queue.Queue()
        self._tun_write_queue = queue.Queue()
        self._rx_rate = utils.Rate()
        self._tx_rate = utils.Rate()
        self._select_tun = not sys.platform.startswith("win")
        # 使用socket解决windows平台下，select不支持tun文件问题
        self._mock_sock = socket.socketpair()

    def __del__(self):
        self._tun.close()

    def _tun_read(self):
        notify = "notify".encode()
        while not self._terminate:
            try:
                p = self._tun.read(2048)
                p = vpn_packet_pack(p, PacketHeader.data)
                # logging.debug("tun read:%s", IP(p).summary())
                self._tun_read_queue.put(p)
                # 发送socket通知，触发socket发送操作
                self._mock_sock[1].send(notify)
            except Exception as e:
                pass

    def _tun_write(self):
        while not self._terminate:
            p = self._tun_write_queue.get()
            # logging.debug("tun write:%s", IP(p).summary())
            try:
                self._tun.write(p)
            except Exception as e:
                pass

    def _heartbeat(self):
        index = 0
        while True:
            time.sleep(1)
            now = time.time()
            if now - self._last_heartbeat_time > 30:
                self._terminate = True
                break

            content = '%d:%f' % (index, now)
            d = vpn_packet_pack(
                content.encode(), PacketHeader.heartbeat)
            self._sock.send(d)

            if not self._show_status:
                continue
            r0 = self._rx_rate.format_status()
            r1 = self._tx_rate.format_status()
            t0 = self._rx_rate.format_total()
            t1 = self._tx_rate.format_total()
            print(
                "Rate(%d) "
                "RX-TX(PPS/BPS): %s/%s-%s/%s "
                "Total(RX/TX): %s/%s" % (
                    index,
                    r0[0], r0[1], r1[0], r1[1],
                    t0[1], t1[1]))
            index += 1

    def negotiate(self):
        while True:
            r, w, _ = select.select([self._sock], [self._sock], [], 1)
            if self._is_server:
                if self._sock not in r:
                    time.sleep(0.5)
                    continue

                data, addr = self._sock.recvfrom(2048)
                t, d = vpn_packet_unpack(data)
                if t == PacketHeader.control and d.decode() == "SYNC":
                    self._peer = addr
                    self._sock.connect(addr)
                    # assert self._sock in w
                    d = vpn_packet_pack(
                        'ACK'.encode(), PacketHeader.control)
                    self._sock.send(d)
                    break
            else:
                if self._sock in w:
                    d = vpn_packet_pack(
                        'SYNC'.encode(), PacketHeader.control)
                    self._sock.send(d)

                if self._sock in r:
                    data, addr = self._sock.recvfrom(2048)
                    t, d = vpn_packet_unpack(data)
                    if t == PacketHeader.control and d.decode() == 'ACK':
                        self._peer = addr
                        break
                else:
                    time.sleep(0.5)

        if self._is_server:
            logging.info("connect server: %s:%d ok" %
                         (self._peer[0], self._peer[1]))
        else:
            logging.info("client connect: %s:%d ok" %
                         (self._peer[0], self._peer[1]))

    def run(self):
        if self._need_negotiate:
            self.negotiate()

        if self._select_tun:
            rs = [self._sock, self._tun.handle]
        else:
            rs = [self._sock, self._mock_sock[0]]
            thread = threading.Thread(target=self._tun_read)
            thread.daemon = True
            thread.start()
            thread = threading.Thread(target=self._tun_write)
            thread.daemon = True
            thread.start()

        thread = threading.Thread(target=self._heartbeat)
        thread.daemon = True
        self._last_heartbeat_time = time.time()
        thread.start()

        ws = []
        while not self._terminate:
            r, w, _ = select.select(rs, ws, [], 5)

            ws = []

            if self._sock in r:
                p = self._sock.recv(2048)
                t, p = vpn_packet_unpack(p)
                if t == PacketHeader.data:
                    self._tun_write_queue.put(p)
                    self._rx_rate.feed(len(p))
                elif t == PacketHeader.heartbeat:
                    self._last_heartbeat_time = time.time()
                    # logging.info("Heartbeat recv:%s", str(p))
                    pass
                elif t == PacketHeader.control:
                    logging.warning(
                        "VPN Packet control message: %s", p.decode())
                elif t == PacketHeader.invalid_type:
                    logging.warning("VPN Packet type invalid!")
                elif t == PacketHeader.invalid_len:
                    logging.warning("VPN Packet len invalid!")
                else:
                    logging.error("VPN Packet type:%d unknow!", t)

            if self._tun.handle in r:
                p = self._tun.read(2048)
                # logging.debug("tun read:%s", IP(p).summary())
                p = vpn_packet_pack(p, PacketHeader.data)
                self._tun_read_queue.put(p)

            if self._mock_sock[0] in r:
                assert not self._select_tun
                self._mock_sock[0].recv(32)  # drop msg
                while self._tun_read_queue.qsize() > 0:
                    p = self._tun_read_queue.get()
                    self._sock.send(p)
                    self._tx_rate.feed(len(p))

            n = self._tun_read_queue.qsize()
            if n > 0:
                if self._sock in w:
                    p = self._tun_read_queue.get()
                    self._sock.send(p)
                    self._tx_rate.feed(len(p))
                    n -= 1
                if n > 0:
                    ws.append(self._sock)

            if not self._select_tun:
                continue

            n = self._tun_write_queue.qsize()
            if n > 0:
                if self._tun.handle in w:
                    p = self._tun_write_queue.get()
                    # logging.debug("tun write:%s", IP(p).summary())
                    self._tun.write(p)
                    n -= 1

                if n > 0:
                    ws.append(self._tun.handle)

        logging.info("VPN Server exit!")


def default_vpn_sock(local=None, peer=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if local:
        s.bind(local)
    s.setblocking(False)
    if peer:
        s.connect(peer)
    return s


def gen_tran_id(l):
    return ''.join(random.choice('0123456789ABCDEF') for i in range(l))


def nat_tunnel_build(server, port, port_try_range, token):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)

    # 1. get peer addr
    peer_addr = None
    while not peer_addr:
        r, w, _ = select.select([s], [s], [], 1)
        if s in r:
            data, _ = s.recvfrom(2048)
            info = data.decode().split(":")
            if len(info) != 2:
                logging.error("Resp:%s from server invalid!", str(info))
                pass
            peer_addr = (info[0], int(info[1]))
            logging.info("Get peer addr: %s:%d", peer_addr[0], peer_addr[1])

        if s in w:
            content = "token:%s" % token
            s.sendto(content.encode(), (server, port))
            if not r:
                time.sleep(0.5)

    local = s.getsockname()
    logging.info("Try to build UDP tunnel(%s:%d=>%s:%d)" % (
        local[0], local[1], peer_addr[0], peer_addr[1]))

    # 2. build tunnel
    port_offset = 0
    sign = 1
    try_times = 0
    start_time = time.time()
    while True:
        r, w, _ = select.select([s], [s], [], 1)

        if s in r:
            data, addr = s.recvfrom(2048)
            if addr[0] != peer_addr[0]:
                continue
            s.connect(addr)
            logging.info("Tunnel ok! peer: %s:%d try times:%d",
                         addr[0], addr[1], try_times)
            return s

        if s in w:
            try_times += 1
            l = int(32 * random.random() + 1)
            content = gen_tran_id(l).encode()
            s.sendto(content, (peer_addr[0], peer_addr[1] + port_offset))
            if False:
                port_offset = int(
                    port_try_range *
                    random.random() - port_try_range/2)
            else:
                port_offset += sign
                if port_offset > port_try_range/2:
                    sign = -1
                elif port_offset < -port_try_range/2:
                    sign = 1
            logging.debug(
                "try next port: %s:%d",
                peer_addr[0], peer_addr[1] + port_offset)

            if not r:
                t = random.random() / 2
                time.sleep(t)
        if time.time() - start_time > 60:
            logging.error("Build udp tunnel timeout!(try times:%d)", try_times)
            break
    s.close()
    return None


def setup_cs_vpn():
    local = ("0.0.0.0", args.port)
    tun = (args.vip, args.vmask, 1400)
    if args.client:
        server = (args.server, args.port)
    else:
        server = None
    s = default_vpn_sock(local, server)
    VPN(not args.client, tun, 1, s, args.show_status).run()


def setup_p2p_vpn():
    if not args.token:
        logging.error("Missing token for p2p vpn!")
        sys.exit()

    tun = (args.vip, args.vmask, 1400)
    s = nat_tunnel_build(
        args.server, args.port,
        args.port_range, args.token)
    VPN(False, tun, 0, s, args.show_status).run()


if __name__ == '__main__':
    args = parse_args()

    set_loggint_format(args.verbose)

    signal.signal(signal.SIGINT, signal_handler)

    while True:
        try:
            if args.cs_vpn:
                setup_cs_vpn()
            else:
                setup_p2p_vpn()
        except Exception as e:
            logging.error("VPN instance exit(%s)", str(e))
            pass

        if not args.run_as_service:
            break
