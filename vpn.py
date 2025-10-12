import os
import sys
import socket
import select
from libs.tuntap import *
import utils
import time
import random
# from scapy.all import *
import threading
import queue

import argparse
import logging
import json
import traceback
import hmac
import hashlib

assert sys.version_info >= (3, 6)

SCRIPT = os.path.abspath(__file__)
PWD = os.path.dirname(SCRIPT)

LOG_LEVELS = (
    logging.NOTSET, logging.DEBUG,
    logging.INFO, logging.WARNING,
    logging.ERROR, logging.CRITICAL)
LOG_CHOICES = list(map(lambda x: logging.getLevelName(x), LOG_LEVELS))


def set_loggint_format(level):
    debug_info = " %(filename)s:%(lineno)d %(funcName)s"

    if args.logfile:
        log_file = os.path.join(PWD, args.logfile)
        log_file_fd = open(log_file, 'w')
    else:
        log_file_fd = sys.stdout

    logging.basicConfig(
        level=level,
        stream=log_file_fd,
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
        "--server", "-s", type=str, required=True, help="server IP")
    parser.add_argument(
        "--server-key", type=str, default=None, help="server authentication key")
    parser.add_argument(
        "--port", "-p", type=int, default=5100,
        help="server port, default 5100")
    parser.add_argument(
        #
        # 当前测试手机热点最大MTU为1341
        #
        "--mtu", type=int, default=1341,
        help="mtu, default 1341")
    parser.add_argument(
        "--timeout", type=int, default=30,
        help="connect timeout, default 30s")
    parser.add_argument(
        "--port-range", "-r", type=int, default=200,
        help="port range, default 200")
    parser.add_argument(
        "--vip", type=str, default="10.0.0.1",
        help="virtual ip, default 10.0.0.1")
    parser.add_argument(
        "--vmask", type=str, default="255.255.255.0",
        help="virtual ip mask, default 255.255.255.0")
    parser.add_argument("--user", type=str, help="user account")
    parser.add_argument("--passwd", type=str, help="user passwd")
    parser.add_argument(
        "--disable-nat-hairpin", action='store_true', help="disable nat hairpin")
    parser.add_argument(
        "--run-as-service", action='store_true', help="run as vpn service")
    parser.add_argument(
        "--p2p-test", action='store_true', help="test p2p throughout")
    parser.add_argument("--logfile", type=str, default=None,
                        help="if set, then running log redirect to file")
    parser.add_argument(
        '--verbose', default=LOG_CHOICES[2],
        choices=LOG_CHOICES, help="log level default:%s" % (LOG_CHOICES[2]))

    return parser.parse_args()


class PacketHeader():
    data = 1
    control = 2
    heartbeat = 3
    heartbeat_ack = 4
    invalid_type = 5
    invalid_len = 6
    format = "!BH"
    format_size = struct.calcsize(format)


class AuthCheckFailed(Exception):
    pass


def vpn_packet_pack(p, t):
    return struct.pack(
        PacketHeader.format, t, len(p)
    ) + p


def vpn_packet_unpack(p):
    if len(p) < PacketHeader.format_size:
        return (PacketHeader.invalid_len, None)
    t, l = struct.unpack_from(PacketHeader.format, p)
    if t >= PacketHeader.invalid_type:
        return (PacketHeader.invalid_type, None)
    if l + PacketHeader.format_size != len(p):
        return (PacketHeader.invalid_len, None)
    return (t, p[PacketHeader.format_size:])


class VPN(object):

    def __init__(self, tun, sock, show_status):
        self._tun = TunTap(nic_type="Tun")
        self._tun.config(tun[0], tun[1], mtu=tun[2])
        assert sock != None
        self._sock = sock
        self._terminate = False
        self._show_status = show_status
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
        self._mock_sock[0].close()
        self._mock_sock[1].close()
        for t in self._threads:
            t.join(timeout=5)
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
        index = -1
        last_rx = 0
        last_tx = 0
        while not self._terminate:
            time.sleep(1)
            index += 1
            r0 = self._rx_rate.format_now()
            r1 = self._tx_rate.format_now()
            a0 = self._rx_rate.format_avg()
            a1 = self._tx_rate.format_avg()
            t0 = self._rx_rate.format_total()
            t1 = self._tx_rate.format_total()

            if last_tx == self._tx_rate.total()[0] and \
                    last_rx == self._rx_rate.total()[0] and \
                    index % 300 != 0:
                continue

            last_tx = self._tx_rate.total()[0]
            last_rx = self._rx_rate.total()[0]
            logging.info(
                "Rate(%s) "
                "RX-TX: %s/%s-%s/%s TOTAL: %s/%s" % (
                    utils.format_time_diff(index),
                    r0[1], a0[1],
                    r1[1], a1[1],
                    t0[1], t1[1]))

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
        need_send_heart_ack = False
        while not self._terminate:
            try:
                r, w, _ = select.select(rs, ws, [], 5)

                ws = []
                now = time.time()

                if now - self._last_recv_data_time > 30:
                    logging.error("Heartbeat timeout!")
                    self._terminate = True
                    break

                if not r and not w:
                    #
                    # request heartbeat if no recv data
                    #
                    #   1. 无数据时，请求发送心跳
                    #   2. 如果接收到数据，则取消心跳发送
                    #
                    need_send_heart = True
                    ws.append(self._sock)
                    continue

                if self._sock in r:
                    d = self._sock.recv(2048)
                    t, p = vpn_packet_unpack(d)
                    if t == PacketHeader.data:
                        self._tun_write_queue.put(p)
                        self._rx_rate.feed(now, len(p))
                        self._last_recv_data_time = now
                        need_send_heart = False
                    elif t == PacketHeader.heartbeat:
                        h = p.decode().split(":")
                        if len(h) == 3:
                            if h[0] != instance_id:
                                self._last_recv_data_time = now
                                need_send_heart = False
                                need_send_heart_ack = True
                                ws.append(self._sock)
                                logging.debug("Heartbeat recv:%s", p.decode())
                            else:
                                logging.warning(
                                    "Heartbeat recv:%s from self", p.decode())
                        pass
                    elif t == PacketHeader.heartbeat_ack:
                        h = p.decode().split(":")
                        if len(h) == 3:
                            if h[0] != instance_id:
                                self._last_recv_data_time = now
                                need_send_heart = False
                                need_send_heart_ack = False
                                logging.debug("Heartbeat ack:%s", p.decode())
                            else:
                                logging.warning(
                                    "Heartbeat ack:%s from self", p.decode())
                        pass
                    elif t == PacketHeader.control:
                        logging.debug(
                            "VPN Packet control message: %s", p.decode())
                    elif t == PacketHeader.invalid_type:
                        logging.warning("VPN Packet type invalid!")
                    elif t == PacketHeader.invalid_len:
                        logging.warning("VPN Packet len invalid!")
                    else:
                        logging.error("VPN Packet type:%d unknow!", t)

                if self._tun.handle in r:
                    d = self._tun.read(2048)
                    # logging.debug("tun read:%s", IP(p).summary())
                    p = vpn_packet_pack(d, PacketHeader.data)
                    self._tun_read_queue.put(p)

                if self._mock_sock[0] in r and self._sock in w:
                    assert not self._select_tun
                    self._mock_sock[0].recv(32)  # drop msg
                    if self._tun_read_queue.qsize() > 0:
                        p = self._tun_read_queue.get()
                        self._sock.send(p)
                        w.remove(self._sock)
                        self._tx_rate.feed(now, len(p))

                n = self._tun_read_queue.qsize()
                if n > 0:
                    if self._sock in w:
                        p = self._tun_read_queue.get()
                        self._sock.send(p)
                        w.remove(self._sock)
                        self._tx_rate.feed(now, len(p))
                        n -= 1
                    if n > 0:
                        ws.append(self._sock)

                if need_send_heart:
                    if self._sock in w:
                        content = f"{instance_id}:{heartbeat_seq_no}:{now}"
                        d = vpn_packet_pack(
                            content.encode(), PacketHeader.heartbeat)
                        self._sock.send(d)
                        need_send_heart = False
                        heartbeat_seq_no += 1
                        w.remove(self._sock)
                        logging.debug(f"Send heartbeat: {content}")
                    else:
                        ws.append(self._sock)

                if need_send_heart_ack:
                    if self._sock in w:
                        content = f"{instance_id}:{heartbeat_seq_no}:{now}"
                        d = vpn_packet_pack(
                            content.encode(), PacketHeader.heartbeat_ack)
                        self._sock.send(d)
                        need_send_heart_ack = False
                        w.remove(self._sock)
                        logging.debug(f"Send heartbeat ack: {content}")
                    else:
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
            except KeyboardInterrupt:
                self._terminate = True
                logging.info(
                    "VPN proc user canceled\n(%s)",
                    traceback.format_exc())
            except Exception:
                self._terminate = True
                logging.error(
                    "VPN proc exit\n(%s)",
                    traceback.format_exc())

        logging.info("VPN Server exit!")


def waiting_nat_peer_online(instance_id, server, port, server_key, user, passwd):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setblocking(False)
        ws = [s]

        challenge = None
        while True:
            r, w, _ = select.select([s], ws, [], 10)
            ws = []
            if s in r:
                data, addr = s.recvfrom(2048)
                try:
                    if addr[0] != server or addr[1] != port:
                        continue

                    info = json.loads(data.decode())
                    if type(info) != dict:
                        logging.error(
                            "Resp:%s from server invalid!", str(info))
                        continue
                except Exception as e:
                    logging.error("Decode %s error(%s)", str(data), str(e))
                    continue

                if "action" in info:
                    action = info["action"]
                    if action == "challenge":
                        if "challenge" not in info:
                            continue

                        if challenge != info["challenge"]:
                            ws.append(s)
                            challenge = info["challenge"]
                    elif action == "server-auth-required":
                        raise AuthCheckFailed("server auth required!")
                    elif action == "server-auth-failed":
                        raise AuthCheckFailed("server auth failed!")
                    elif action == "peer-auth-failed":
                        raise AuthCheckFailed("peer auth failed!")
                    elif action == "peer-ready":
                        if "token" not in info:
                            raise Exception(
                                "response format error!(%s)", str(info))
                        return info["token"]
                    else:
                        logging.error("Unknow action:%s", action)
                        continue

            if s in w:
                content = {
                    "user": user,
                    "instance_id": instance_id,
                    "action": "wait-peer",
                }

                if challenge:
                    content["auth"] = hmac.new(
                        challenge.encode(),
                        (user+passwd).encode(),
                        digestmod='md5'
                    ).hexdigest()[:16]
                    if server_key:
                        content["server-auth"] = hmac.new(
                            challenge.encode(),
                            server_key.encode(),
                            digestmod='md5'
                        ).hexdigest()[:16]
                s.sendto(json.dumps(content).encode(), (server, port))

            if not r and not w:
                ws.append(s)


def nat_tunnel_build(
        instance_id, server, port, port_try_range,
        user, token, timeout, disable_nat_hairpin=False, request_forward=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    s.bind(("0.0.0.0", 0))  # 绑定一个本地地址和随机端口
    local = s.getsockname()

    # 1. get peer addr
    peer_public_addr = None
    start_time = time.time()
    ws = [s]
    while not peer_public_addr:
        r, w, _ = select.select([s], ws, [], 0.5)
        ws = []

        if s in r:
            data, addr = s.recvfrom(2048)
            try:
                if addr[0] != server or addr[1] != port:
                    continue

                info = json.loads(data.decode())
                if type(info) != dict:
                    logging.error("Resp:%s from server invalid!", str(info))
                    continue
            except Exception as e:
                logging.error("Decode %s error(%s)", str(data), str(e))
                continue

            logging.debug("Resp:%s from server", str(info))
            key_missing = False
            for k in ["peer-public-addr", "peer-local-addr", "public-addr"]:
                if k not in info:
                    key_missing = True
                    logging.error("Resp:%s missing key:%s!", str(info), k)
                    break

            if key_missing:
                continue

            peer_public_addr = info["peer-public-addr"]
            peer_local_addr = info["peer-local-addr"]
            public_addr = info["public-addr"]
            if not request_forward:
                logging.info(
                    "Get addr %s:%d=>%s:%d ok",
                    public_addr[0], public_addr[1], peer_public_addr[0], peer_public_addr[1])
            else:
                logging.info(
                    "Forward tunnel %s:%d=>%s:%d ok",
                    public_addr[0], public_addr[1], peer_public_addr[0], peer_public_addr[1])
                s.connect((server, port))
                return s

        if s in w:
            content = {
                "user": user,
                "instance_id": instance_id,
                "token": token,
                "action": "peer-info" if not request_forward else "request-forward",
                "local-addr": local
            }
            s.sendto(json.dumps(content).encode(), (server, port))

        if time.time() - start_time > timeout:
            logging.error("Get peer info timeout(%ds)", timeout)
            s.close()
            return None

        if not r and not w:
            ws.append(s)

    # 2. NAT-HAIRPIN
    if not request_forward and public_addr[0] == peer_public_addr[0]:
        # 2.1 check in save LAN
        port_local = local[1]
        port_remote = peer_local_addr[1]
        is_server = port_local > port_remote and public_addr[1] > peer_public_addr[1]

        s.close()  # 让出本地端口，探测完重新创建
        logging.info(
            f"Checking peer={peer_public_addr[0]}:{peer_public_addr[1]} in same LAN...")
        local_ip, remote_ip = utils.probe_ip_in_lan(
            port_local, port_remote, is_server)

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setblocking(False)
        if local_ip and remote_ip:
            s.bind((local_ip, port_local))
            s.connect((remote_ip, port_remote))
            logging.info(
                f"LAN tunnel {local_ip}:{port_local}=>{remote_ip}:{port_remote} ok")
            return s
        else:
            s.bind(("0.0.0.0", port_local))
            if not disable_nat_hairpin:
                s.connect(tuple(peer_public_addr))
                logging.info(
                    f"Nat-hairpin tunnel {local[0]}:{local[1]}=>{peer_public_addr[0]}:{peer_public_addr[1]} ok")
                return s

    # 3. build tunnel
    logging.info(
        f"Try to build UDP tunnel {local[0]}:{local[1]}=>{peer_public_addr[0]}:{peer_public_addr[1]}")

    port_offset0 = 0
    port_offset1 = 0
    sign0 = 1
    sign1 = -1
    try_times = 0
    start_time = time.time()
    ws = [s]
    select_timeout = 0.1
    send_tag = hashlib.md5(
        (user + peer_public_addr[0]).encode()).hexdigest()[:16]
    recv_tag = hashlib.md5((user + public_addr[0]).encode()).hexdigest()[:16]

    recv_req_ok = False
    ack_time = 10  # 收到req之后继续再发送10次，确保对方能收到resp消息
    while True:
        r, w, _ = select.select([s], ws, [], select_timeout)
        ws = []

        if s in r:
            data, addr = s.recvfrom(2048)
            try:
                t, d = vpn_packet_unpack(data)
                if t == PacketHeader.control:
                    ds = d.decode().split(":")
                    if len(ds) == 3 and ds[0] == recv_tag and addr[0] == peer_public_addr[0]:
                        s.connect(addr)
                        if ds[1] == "nat-req":
                            recv_req_ok = True
                            logging.info(
                                f"Tunnel req from {addr[0]}:{addr[1]} try times:{try_times}")
                        elif ds[1] == "nat-resp":
                            logging.info(
                                f"Tunnel ok! peer:{addr[0]}:{addr[1]} try times:{try_times}")
                            return s
                        else:
                            logging.warning(f"Unknow tunnel msg: {d}")
                    else:
                        logging.warning(f"Invalid control msg: {d}")
                elif t < PacketHeader.invalid_type:
                    logging.debug(f"skip tunnel packet:{t} {d}")
                else:
                    logging.warning(f"Invalid packet:{t} {d}")
            except Exception as e:
                pass

        if s in w:
            if not recv_req_ok:
                try_times += 1
                l = int(32 * random.random() + 1)

                content = vpn_packet_pack(
                    (send_tag + ":nat-req:" + utils.random_str(l)).encode(),
                    PacketHeader.control)
                s.sendto(
                    content, (peer_public_addr[0], peer_public_addr[1] + port_offset0))
                s.sendto(
                    content, (peer_public_addr[0], peer_public_addr[1] + port_offset1))
                if False:
                    port_offset0 = int(
                        port_try_range *
                        random.random() - port_try_range/2)
                    port_offset1 = int(
                        port_try_range *
                        random.random() - port_try_range/2)
                else:
                    port_offset0 += sign0
                    port_offset1 += sign1
                    if port_offset0 > port_try_range/2 or peer_public_addr[1] + port_offset0 == 65536:
                        sign0 = -1
                    elif port_offset0 < -port_try_range/2 or peer_public_addr[1] + port_offset0 == 1:
                        sign0 = 1
                    if port_offset1 > port_try_range/2 or peer_public_addr[1] + port_offset1 == 65536:
                        sign1 = -1
                    elif port_offset1 < -port_try_range/2 or peer_public_addr[1] + port_offset1 == 1:
                        sign1 = 1
                logging.debug(
                    "try next port(%d): %s:(%d,%d)", try_times,
                    peer_public_addr[0],
                    peer_public_addr[1] + port_offset0,
                    peer_public_addr[1] + port_offset1)
            else:
                l = int(32 * random.random() + 1)
                content = vpn_packet_pack(
                    (send_tag + ":nat-resp:" + utils.random_str(l)).encode(),
                    PacketHeader.control)
                s.send(content)
                ack_time -= 1
                if ack_time == 0:
                    logging.info(f"Tunnel ok! peer:{addr[0]}:{addr[1]}")
                    return s
            if not r:
                t = random.random() / 5
                select_timeout = t

        if not r and not w:
            ws.append(s)

        if time.time() - start_time > timeout:
            logging.error(f"Build udp tunnel timeout!(try times:{try_times})")
            break
    s.close()
    return None


def setup_cs_vpn(instance_id):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
        logging.info(f"connect server: {peer[0]}:{peer[1]} ok")
    else:
        logging.info(f"client connect: {peer[0]}:{peer[1]} ok")
    tun = (args.vip, args.vmask, args.mtu)
    with VPN(tun, s, args.show_status) as v:
        v.run()


def test_throughput(s, duration):
    time_last = time.time()
    seconds = 0
    data = 1400*'X'
    rx_rate = utils.Rate()
    tx_rate = utils.Rate()
    while seconds < duration:
        r, w, _ = select.select([s], [s], [], 1)
        now = time.time()
        if s in r:
            d = s.recv(2048)
            _, d = vpn_packet_unpack(d)
            rx_rate.feed(now, len(d.decode()))
        if s in w:
            d = vpn_packet_pack(data.encode(), PacketHeader.data)
            l = s.send(d)
            tx_rate.feed(now, l)

        if time_last + 1 < time.time():
            time_last = now
            r0 = rx_rate.format_now()
            r1 = tx_rate.format_now()
            a0 = rx_rate.format_avg()
            a1 = tx_rate.format_avg()
            t0 = rx_rate.format_total()
            t1 = tx_rate.format_total()
            logging.info(
                "Rate(%s) "
                "RX-TX: %s/%s-%s/%s TOTAL: %s/%s" % (
                    utils.format_time_diff(seconds),
                    r0[1], a0[1],
                    r1[1], a1[1],
                    t0[1], t1[1]))
            seconds += 1
    s.close()


def setup_p2p_vpn(instance_id):
    if not args.user or not args.passwd:
        logging.error("Missing user or passwd for p2p vpn!")
        sys.exit()

    tun = (args.vip, args.vmask, args.mtu)
    server = socket.gethostbyname(args.server)

    # do waiting peer online
    logging.info("Instance %s Waiting peer online...", instance_id)
    token = waiting_nat_peer_online(
        instance_id, server,
        args.port, args.server_key,
        args.user, args.passwd)
    logging.info("Begin building NAT-Tunnel...")
    s = nat_tunnel_build(
        instance_id, server, args.port,
        args.port_range, args.user, token,
        args.timeout,
        disable_nat_hairpin=args.disable_nat_hairpin)
    if not s:
        logging.error("NAT Tunnel build timeout!")
        s = nat_tunnel_build(
            instance_id, server, args.port,
            args.port_range, args.user, token,
            min(args.timeout, 30),
            disable_nat_hairpin=args.disable_nat_hairpin,
            request_forward=True)
        if not s:
            logging.error("Forward Tunnel build timeout!")
            return
    elif args.p2p_test:
        test_throughput(s, 30)
        logging.info("P2P throught test finish!")
        return

    with VPN(tun, s, args.show_status) as v:
        v.run()


if __name__ == '__main__':
    args = parse_args()
    set_loggint_format(args.verbose)

    instance_id = utils.device_id()

    fail_try_time = 0
    wait_time = 5
    while True:
        normal_exit = False
        try:
            t = time.time()
            if args.cs_vpn:
                setup_cs_vpn(instance_id)
            else:
                setup_p2p_vpn(instance_id)
            if time.time() - t > 5:
                normal_exit = True
                # 恢复计数
                fail_try_time = 0
        except (socket.gaierror, OSError) as e:
            logging.warning("VPN instance exit(%s)", traceback.format_exc())
        except AuthCheckFailed as e:
            logging.warning("VPN instance exit(%s)", traceback.format_exc())
        except Exception as e:
            logging.error("VPN instance exit\n%s", traceback.format_exc())
            pass

        if not args.run_as_service or args.p2p_test:
            break

        if not normal_exit:
            if fail_try_time * wait_time > 1800:
                # 超过30分钟不恢复，恢复计数重试
                fail_try_time = 0
            else:
                fail_try_time += 1

        # 避免无限失败请求
        time.sleep((fail_try_time + 1) * wait_time)
