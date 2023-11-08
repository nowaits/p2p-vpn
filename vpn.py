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
import json
import traceback

assert sys.version_info >= (3, 6)

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
        "--port", "-p", type=int, default=5100,
        help="server port, default 5100")
    parser.add_argument(
        "--mtu", type=int, default=1400,
        help="mtu, default 1400")
    parser.add_argument(
        "--timeout", type=int, default=60,
        help="connect timeout, default 60s")
    parser.add_argument(
        "--port-range", "-r", type=int, default=500,
        help="port range, default 500")
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

    def __init__(self, tun, sock, show_status):
        self._tun = TunTap(nic_type="Tun", nic_name="tun0")
        self._tun.config(tun[0], tun[1], mtu=tun[2])
        assert sock != None
        self._sock = sock
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
        self._threads = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        assert self._terminate
        self._tun.close()
        self._sock.close()
        for t in self._threads:
            t.join()
        logging.info("VPN closed!")

    def _tun_read(self):
        notify = "notify".encode()
        while not self._terminate:
            try:
                p = self._tun.read(2048)
                if not p:
                    continue
                p = vpn_packet_pack(p, PacketHeader.data)
                # logging.debug("tun read:%s", IP(p).summary())
                self._tun_read_queue.put(p)
                # 发送socket通知，触发socket发送操作
                self._mock_sock[1].send(notify)
            except Exception as e:
                traceback.print_exc()
                pass

        logging.info("tun read thread exit!")

    def _tun_write(self):
        while not self._terminate:
            try:
                p = self._tun_write_queue.get(timeout=1)
            except Exception as e:
                continue

            # logging.debug("tun write:%s", IP(p).summary())
            try:
                self._tun.write(p)
            except Exception as e:
                traceback.print_exc()
                pass

        logging.info("tun write thread exit!")

    def _status(self):
        index = 0
        while not self._terminate:
            time.sleep(1)
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

        logging.info("status thread exit!")

    def run(self):
        if self._select_tun:
            rs = [self._sock, self._tun.handle]
        else:
            rs = [self._sock, self._mock_sock[0]]
            thread = threading.Thread(target=self._tun_read)
            thread.daemon = True
            thread.start()
            self._threads.append(thread)
            thread = threading.Thread(target=self._tun_write)
            thread.daemon = True
            thread.start()
            self._threads.append(thread)

        if self._show_status:
            thread = threading.Thread(target=self._status)
            thread.daemon = True
            thread.start()
            self._threads.append(thread)
        self._last_recv_data_time = time.time()

        ws = []
        heartbeat_seq_no = 0
        need_send_heart = False
        while not self._terminate:
            r, w, _ = select.select(rs, ws, [], 2)

            ws = []

            if not r and not w:
                #
                # request heartbeat if no recv data
                #
                #   1. 无数据时，请求发送心跳
                #   2. 如果接收到数据，则取消心跳发送
                #
                need_send_heart = True
                ws.append(self._sock)

                now = time.time()
                if now - self._last_recv_data_time > 30:
                    logging.error("Heartbeat timeout!")
                    self._terminate = True
                continue

            if self._sock in r:
                p = self._sock.recv(2048)
                t, p = vpn_packet_unpack(p)
                if t == PacketHeader.data:
                    now = time.time()
                    self._tun_write_queue.put(p)
                    self._rx_rate.feed(now, len(p))
                    self._last_recv_data_time = now
                    need_send_heart = False
                elif t == PacketHeader.heartbeat:
                    now = time.time()
                    self._last_recv_data_time = now
                    need_send_heart = False
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

            if self._mock_sock[0] in r and self._sock in w:
                assert not self._select_tun
                self._mock_sock[0].recv(32)  # drop msg
                if self._tun_read_queue.qsize() > 0:
                    p = self._tun_read_queue.get()
                    self._sock.send(p)
                    w.remove(self._sock)
                    self._tx_rate.feed(time.time(), len(p))

            n = self._tun_read_queue.qsize()
            if n > 0:
                if self._sock in w:
                    p = self._tun_read_queue.get()
                    self._sock.send(p)
                    w.remove(self._sock)
                    self._tx_rate.feed(time.time(), len(p))
                    n -= 1
                if n > 0:
                    ws.append(self._sock)

            if need_send_heart and self._sock in w:
                content = '%d:%f' % (heartbeat_seq_no, time.time())
                d = vpn_packet_pack(
                    content.encode(), PacketHeader.heartbeat)
                self._sock.send(d)
                need_send_heart = False
                heartbeat_seq_no += 1
                logging.debug("Send heartbeat")

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


def nat_tunnel_build(server, port, port_try_range, user, timeout, request_forward=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)

    # 1. get peer addr
    peer_addr = None
    while not peer_addr:
        r, w, _ = select.select([s], [s], [], 1)
        if s in r:
            data, _ = s.recvfrom(2048)
            try:
                info = json.loads(data.decode())
            except Exception as e:
                logging.error("Decode %s error(%s)", str(data), str(e))
                continue

            if type(info) != dict or "addr" not in info or "port" not in info:
                logging.error("Resp:%s from server invalid!", str(info))
                pass

            peer_addr = (info["addr"], int(info["port"]))
            if not request_forward:
                logging.info("Get peer addr: %s:%d",
                             peer_addr[0], peer_addr[1])
            else:
                logging.info("Forward tunnel with peer addr: %s:%d ok!",
                             peer_addr[0], peer_addr[1])
                s.connect((server, port))
                return s

        if s in w:
            content = json.dumps({
                "user": user,
                "action": "peer-info" if not request_forward else "request-forward"
            })
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
            content = utils.random_str(l).encode()
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
                "try next port(%d): %s:%d", try_times,
                peer_addr[0], peer_addr[1] + port_offset)

            if not r:
                t = random.random() / 10
                time.sleep(t)
        if time.time() - start_time > timeout:
            logging.error("Build udp tunnel timeout!(try times:%d)", try_times)
            break
    s.close()
    return None


def setup_cs_vpn():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    if args.client:
        s.connect((args.server, args.port))
    else:
        s.bind(("0.0.0.0", args.port))

    # negotiate
    peer = None
    while True:
        r, w, _ = select.select([s], [s], [], 1)
        if not args.client:
            if s not in r:
                time.sleep(0.5)
                continue

            data, addr = s.recvfrom(2048)
            t, d = vpn_packet_unpack(data)
            if t == PacketHeader.control and d.decode() == "SYNC":
                peer = addr
                s.connect(addr)
                # assert s in w
                d = vpn_packet_pack(
                    'ACK'.encode(), PacketHeader.control)
                s.send(d)
                break
        else:
            if s in w:
                d = vpn_packet_pack(
                    'SYNC'.encode(), PacketHeader.control)
                s.send(d)

            if s in r:
                data, addr = s.recvfrom(2048)
                t, d = vpn_packet_unpack(data)
                if t == PacketHeader.control and d.decode() == 'ACK':
                    peer = addr
                    break
            else:
                time.sleep(0.5)

    if not args.client:
        logging.info("connect server: %s:%d ok" %
                     (peer[0], peer[1]))
    else:
        logging.info("client connect: %s:%d ok" %
                     (peer[0], peer[1]))
    tun = (args.vip, args.vmask, 1400)
    with VPN(tun, s, args.show_status) as v:
        v.run()


def setup_p2p_vpn():
    if not args.token:
        logging.error("Missing token for p2p vpn!")
        sys.exit()

    tun = (args.vip, args.vmask, args.mtu)
    s = nat_tunnel_build(
        args.server, args.port,
        args.port_range, args.token,
        args.timeout)
    if not s:
        logging.error("NAT Tunnel build timeout!")
        s = nat_tunnel_build(
            args.server, args.port,
            args.port_range, args.token,
            args.timeout,
            request_forward=True)

    with VPN(tun, s, args.show_status) as v:
        v.run()


if __name__ == '__main__':
    args = parse_args()
    set_loggint_format(args.verbose)

    while True:
        try:
            if args.cs_vpn:
                setup_cs_vpn()
            else:
                setup_p2p_vpn()
        except Exception as e:
            logging.error("VPN instance exit(%s)", str(e))
            traceback.print_exc()
            pass

        if not args.run_as_service:
            break
