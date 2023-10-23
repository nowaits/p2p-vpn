import sys
import socket
import select
from libs.tuntap import *
import utils
import time
import signal
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
    parser = argparse.ArgumentParser(description="proxy")

    parser.add_argument(
        "--client", "-c", action='store_true',  help="client mode")
    parser.add_argument(
        "--status", "-u", action='store_true',  help="show status")
    parser.add_argument("--server", "-s", type=str,
                        default="192.168.20.1", help="server IP")
    parser.add_argument("--port", "-p", type=int,
                        default=4593, help="server port, default 4593")
    parser.add_argument("--vip", "-i", type=str,
                        default="10.0.0.1", help="virtual ip, default 10.0.0.1")
    parser.add_argument("--vmask", "-m", type=str,
                        default="255.255.255.0", help="virtual ip mask, default 255.255.255.0")
    parser.add_argument(
        '--verbose', "-v", default=LOG_CHOICES[2], choices=LOG_CHOICES, help="log level")

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

    def __init__(self, is_server, tun, local, peer):
        self._is_server = is_server
        self._tun = TunTap(nic_type="Tun", nic_name="tun0")
        self._tun.config(tun[0], tun[1], mtu=tun[2])
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(local)
        self._sock.setblocking(False)
        self._peer = None
        self._tun.mtu = tun[2]
        self._tun_read_queue = queue.Queue()
        self._tun_write_queue = queue.Queue()
        self._rx_rate = utils.Rate()
        self._tx_rate = utils.Rate()
        if not is_server:
            self._sock.connect(peer)
        self._select_tun = not sys.platform.startswith("win")
        # 使用socket解决windows平台下，select不支持tun文件问题
        self._mock_sock = socket.socketpair()

    def __del__(self):
        self._tun.close()

    def _tun_read(self):
        notify = "notify".encode()
        while True:
            try:
                p = self._tun.read(2048)
                p = vpn_packet_pack(p, PacketHeader.data)
                #logging.debug("tun read:%s", IP(p).summary())
                self._tun_read_queue.put(p)
                # 发送socket通知，触发socket发送操作
                self._mock_sock[1].send(notify)
            except Exception as e:
                pass

    def _tun_write(self):
        while True:
            p = self._tun_write_queue.get()
            #logging.debug("tun write:%s", IP(p).summary())
            try:
                self._tun.write(p)
            except Exception as e:
                pass

    def _heartbeat(self):
        index = 0
        while True:
            time.sleep(1)
            now = time.time()

            content = '%d:%f' % (index, now)
            d = vpn_packet_pack(
                content.encode(), PacketHeader.heartbeat)
            self._sock.send(d)

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
                    #assert self._sock in w
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
        thread.start()

        ws = []
        while True:
            r, w, _ = select.select(rs, ws, [], 5)

            ws = []

            if self._sock in r:
                p = self._sock.recv(2048)
                t, p = vpn_packet_unpack(p)
                if t == PacketHeader.data:
                    self._tun_write_queue.put(p)
                    self._rx_rate.feed(len(p))
                elif t == PacketHeader.heartbeat:
                    #logging.info("Heartbeat recv:%s", str(p))
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
                #logging.debug("tun read:%s", IP(p).summary())
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
                    #logging.debug("tun write:%s", IP(p).summary())
                    self._tun.write(p)
                    n -= 1

                if n > 0:
                    ws.append(self._tun.handle)


if __name__ == '__main__':
    args = parse_args()

    set_loggint_format(args.verbose)

    signal.signal(signal.SIGINT, signal_handler)

    local = ("0.0.0.0", args.port)
    if args.client:
        server = (args.server, args.port)
        tun = (args.vip, args.vmask, 1400)
    else:
        server = None
        tun = (args.vip, args.vmask, 1400)

    VPN(not args.client, tun, local, server).run()
