import sys
import socket
import select
import threading
import logging
import utils
import argparse
import os
import time
import traceback
import struct
import json
from collections import deque
import hashlib

SCRIPT = os.path.abspath(__file__)
PWD = os.path.dirname(SCRIPT)


assert sys.version_info >= (3, 6)

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

    def parse_maps(str):
        m = []
        protos = {"tcp": socket.SOCK_STREAM, "udp": socket.SOCK_DGRAM}
        for a in str.split(","):
            p0, p1, p2 = a.split(":")
            m.append((protos[p0], int(p1), int(p2)))
        return m

    parser = argparse.ArgumentParser(description="port forward")

    parser.add_argument(
        "--is-tunnel-server", action='store_true', help="is tunnel server, default: false")
    parser.add_argument(
        "--show-status", default="true", type=str2bool, help="show status")
    parser.add_argument(
        "--ip", type=str, default="0.0.0.0", help="agent/server IP")
    parser.add_argument(
        "--server-key", type=str, default=None, help="server authentication key")
    parser.add_argument(
        "--status-period", type=int, default=300, help="status-period, default:5min")
    parser.add_argument(
        "--port", type=int, default=5100,
        help="agent/server, default 5100")
    parser.add_argument(
        "--local-port-map", type=parse_maps, default=[],
        help="local port maps: <tcp/udp>:<local-port0>:<remote-port0>,<tcp/udp>:<local-port1>:<remote-port1>")
    parser.add_argument(
        "--remote-port-map", type=parse_maps, default=[],
        help="remote port maps: <tcp/udp>:<local-port0>:<remote-port0>,<tcp/udp>:<local-port1>:<remote-port1>")
    parser.add_argument(
        "--logfile", type=str, default=None,
        help="if set, then running log redirect to file")
    parser.add_argument(
        '--verbose', default=LOG_CHOICES[2],
        choices=LOG_CHOICES, help="log level default:%s" % (LOG_CHOICES[2]))

    return parser.parse_args()


class UserAbort(Exception):
    pass


class AuthFailed(Exception):
    pass


class TunnelOffline(Exception):
    pass


class STATS():
    tx_cache_idx = 0
    rx_cache_idx = tx_cache_idx + 1
    client_to_tunnel_idx = rx_cache_idx + 1
    tunnel_to_target_idx = client_to_tunnel_idx + 1
    stats_max_idx = tunnel_to_target_idx + 1
    MTU = 2048
    restart_times = 0
    workers = {}

    def status(alive):

        if not STATS.workers:
            logging.warning("no workers!")
            return

        # [rx bps, tx bps]
        rate_now = [0, 0]
        rate_avg = [0, 0]
        rate_total = [0, 0]

        tx_cache = 0
        rx_cache = 0
        client_to_tunnel = 0
        tunnel_to_target = 0

        for _, w in STATS.workers.items():
            r, t = w.rate()
            s = w.stats()

            tx_cache += s[STATS.tx_cache_idx]
            rx_cache += s[STATS.rx_cache_idx]
            client_to_tunnel += s[STATS.client_to_tunnel_idx]
            tunnel_to_target += s[STATS.tunnel_to_target_idx]

            rate_now[0] += r.now()[1]
            rate_now[1] += t.now()[1]

            rate_avg[0] += r.avg()[1]
            rate_avg[1] += t.avg()[1]

            rate_total[0] += r.total()[1]
            rate_total[1] += t.total()[1]

        msg1 = \
            "Rate(%s) Worker(%d): %d CLIENTS: %d/%d " \
            "RX-TX: %s/%s-%s/%s TOTAL: %s/%s" % (
                utils.format_time_diff(alive),
                STATS.restart_times,
                len(STATS.workers.items()),
                client_to_tunnel, tunnel_to_target,

                utils.rate_format_str(rate_now[0]),
                utils.rate_format_str(rate_avg[0]),

                utils.rate_format_str(rate_now[1]),
                utils.rate_format_str(rate_avg[1]),

                utils.rate_format_str(rate_total[0]),
                utils.rate_format_str(rate_total[1]))

        if tx_cache != 0 or rx_cache != 0:
            msg2 = " Cache: %d/%d" % (tx_cache, rx_cache)
        else:
            msg2 = ""

        logging.info("%s%s", msg1, msg2)


class PacketHeader():
    data = 1
    session_create = 2
    session_destroy = 3
    port_map = 4
    # type + proto + client port + target port + len(data len)
    format = "!BBHHH"
    format_size = struct.calcsize(format)


def tunnel_packet_pack(p, t, proto, lport, rport):
    return struct.pack(
        PacketHeader.format, t, proto, lport, rport, len(p)
    ) + p


class PortForwardWorker(object):
    def __init__(self, tunnel_sock):
        self._tunnel_sock = tunnel_sock
        self._id = tunnel_sock.fileno()
        self._port_maps = {}
        self._rx_rate = utils.Rate()
        self._tx_rate = utils.Rate()
        # <fid, [tx cache, rx cache，client_idx, target_idx]>
        self._status = STATS.stats_max_idx * [0]

        self._rs = [self._tunnel_sock]
        self._ws = []

        self._tunnel_sock.setblocking(False)
        self._tunnel_sock.settimeout(30)

        STATS.workers[self._id] = self

    def id(self):
        return self._id

    def setup_map_sock(self, port_maps_conf):
        added_port_map = []

        for p in port_maps_conf:
            assert p[0] == socket.SOCK_STREAM
            try:
                s = socket.socket(socket.AF_INET, p[0])
                s.setsockopt(socket.SOL_SOCKET,
                             socket.SO_REUSEADDR, 1)
                s.setblocking(False)
                s.bind(("0.0.0.0", p[1]))
                s.listen(10)
                added_port_map.append(s)
            except Exception:
                emsg = "Port Forward instance exit\n%s" % (
                    traceback.format_exc())
                logging.error("%s", emsg)

                # close listen socket
                for s in added_port_map:
                    del self._port_maps[s.fileno()]
                    s.close()

                return False
            self._port_maps[s.fileno()] = [s, p]

        # add rs array
        for s in added_port_map:
            self._rs.append(s)

        return True

    def rate(self):
        return (self._rx_rate, self._tx_rate)

    def stats(self):
        return self._status

    def terminate(self):
        self._terminate = True

    def set_pending_write(self, s):
        if s in self._ws:
            return
        self._ws.append(s)

    def unset_pending_write(self, s):
        if s not in self._ws:
            return
        self._ws.remove(s)

    def flush_tx(self, q, s):
        _pkts = 0
        _bytes = 0
        while q:
            p = q.popleft()
            try:
                a = s.send(p)
                _bytes += a
                if a != len(p):
                    p = p[a:]
                    q.insert(0, p)
                    break
            except (ConnectionResetError, BlockingIOError):
                q.insert(0, p)
                break
            _pkts += 1
        return (_pkts, _bytes)

    def do_main_proc(self):
        self._tunnel_sock.setblocking(False)

        self._last_recv_data_time = time.time()

        data_buffer = bytes()

        clients = {}
        clients_fds = {}

        tunnel_tx_queue = deque()

        stats_last_update_time = time.time()

        def close_client(s):
            s_fid = s.fileno()
            info = clients_fds[s_fid]
            self._rs.remove(s)
            self.unset_pending_write(s)

            addr = info[6]

            self._status[STATS.rx_cache_idx] -= len(info[1])

            self._status[info[5]] -= 1
            logging.info(
                "Forward %s session %s %s:%d => %s:%d stop!",
                "client -> tunnel" if info[5] == STATS.client_to_tunnel_idx else "tunnel -> target",
                "tcp" if info[2] == socket.SOCK_STREAM else "udp",
                addr[0], addr[1], addr[2], addr[3])

            k = "%d-%d-%d" % (info[2], info[3], info[4])
            s.close()
            # client info
            del clients[k]
            del clients_fds[s_fid]

        self._terminate = False
        while not self._terminate:
            try:
                r, w, _ = select.select(self._rs, self._ws, [], 1)
            except KeyboardInterrupt:
                logging.error("Forward Worker proc exist!")
                break

            self._ws = []
            now = time.time()

            for sock in r:
                self._last_recv_data_time = now
                fid = sock.fileno()
                assert fid != -1

                if sock == self._tunnel_sock:
                    try:
                        _e = None
                        data = sock.recv(STATS.MTU)
                    except ConnectionResetError:
                        _e = TunnelOffline("tunnel offline")
                    except TimeoutError:
                        _e = TunnelOffline("tunnel timeout")
                    finally:
                        if _e:
                            raise _e

                    if not data:
                        logging.warning("Forward Worker peer closed!")
                        self._terminate = True
                        break

                    data_buffer += data
                    while len(data_buffer) >= PacketHeader.format_size:
                        t, stype, client_port, target_port, l = struct.unpack_from(
                            PacketHeader.format, data_buffer)
                        assert l <= STATS.MTU
                        if PacketHeader.format_size + l > len(data_buffer):
                            # logging.debug(
                            #     "need for data!(%d/%d)",
                            #     len(data_buffer), PacketHeader.format_size + l)
                            break
                        else:
                            p = data_buffer[PacketHeader.format_size:PacketHeader.format_size+l]
                            data_buffer = data_buffer[PacketHeader.format_size+l:]

                        if t == PacketHeader.data:
                            k = "%d-%d-%d" % (stype, client_port, target_port)
                            if k not in clients:
                                logging.debug(
                                    "No forward session %s %d => %d! %d/%d",
                                    "tcp" if stype else "udp",
                                    client_port, target_port, l, len(data_buffer))
                                continue

                            s = clients[k][0]
                            info = clients_fds[s.fileno()]
                            tx_queue = info[1]
                            tx_queue.append(p)

                            self._status[STATS.rx_cache_idx] += 1
                            try:
                                _pkts, _bytes = self.flush_tx(tx_queue, s)
                            except BrokenPipeError:
                                # 对端已经关闭
                                close_client(s)

                                # 避免后续发送轮询失败
                                if s in w:
                                    w.remove(s)
                                continue
                            self._status[STATS.rx_cache_idx] -= _pkts

                            if tx_queue:
                                self.set_pending_write(s)

                            self._rx_rate.feed(now, len(p))
                            if self._status[STATS.rx_cache_idx] >= 512:
                                # 避免发送累积过多处理不及时，导致整体性能低
                                break
                        elif t == PacketHeader.session_create:
                            k = "%d-%d-%d" % (stype, client_port, target_port)
                            if k in clients:
                                continue

                            s = socket.socket(socket.AF_INET, stype)
                            s.setsockopt(socket.SOL_SOCKET,
                                         socket.SO_REUSEADDR, 1)
                            try:
                                s.connect(("127.0.0.1", target_port))
                            except:
                                logging.info(
                                    "Connect target port:%d faild\n%s",
                                    target_port, traceback.format_exc())
                                s.close()
                                continue
                            s.setblocking(False)
                            s.settimeout(30)
                            clients[k] = (
                                s, stype, client_port, target_port)
                            assert s.fileno() not in clients

                            la = s.getsockname()
                            ra = s.getpeername()

                            tx_queue = deque()
                            clients_fds[s.fileno()] = (
                                s, tx_queue, stype,
                                client_port, target_port, STATS.tunnel_to_target_idx,
                                (la[0], la[1], ra[0], ra[1]))

                            #
                            # 插入位置前于tunnel_sock，避免轮询时，tunnel_sock提前关闭client
                            #
                            self._rs.insert(0, s)

                            self._status[STATS.tunnel_to_target_idx] += 1
                            logging.info(
                                "Forward tunnel -> target session %s %s:%d => %s:%d start!",
                                "tcp" if stype == socket.SOCK_STREAM else "udp",
                                la[0], la[1], ra[0], ra[1])
                        elif t == PacketHeader.session_destroy:
                            k = "%d-%d-%d" % (stype, client_port, target_port)
                            if k in clients:
                                s = clients[k][0]
                                close_client(s)
                                # 避免后续发送轮询失败
                                if s in w:
                                    w.remove(s)
                            else:
                                logging.info("unknow destroy")
                        elif t == PacketHeader.port_map:
                            try:
                                info = json.loads(p.decode())
                            except Exception as e:
                                logging.error(
                                    "Recv invalid port map conf: (%s)", str(p))
                                continue

                            if not self.setup_map_sock(info):
                                self._terminate = True
                                logging.error(
                                    "Setup Recv conf: (%s) failded", str(p))
                        else:
                            raise Exception("Unknow packet type:%d!", t)
                elif fid in self._port_maps:
                    listen_port_info = self._port_maps[fid][1]
                    s, ra = sock.accept()
                    s.setblocking(False)
                    s.settimeout(30)
                    la = s.getsockname()
                    assert la[1] == listen_port_info[1]

                    client_port = ra[1]
                    k = "%d-%d-%d" % (
                        listen_port_info[0], client_port, listen_port_info[2])
                    tx_queue = deque()
                    clients[k] = (
                        s, listen_port_info[0], client_port, listen_port_info[2])
                    clients_fds[s.fileno()] = (
                        s, tx_queue, listen_port_info[0],
                        client_port, listen_port_info[2], STATS.client_to_tunnel_idx,
                        (la[0], la[1], ra[0], ra[1]))

                    #
                    # 插入位置前于tunnel_sock，避免轮询时，tunnel_sock提前关闭client
                    #
                    self._rs.insert(0, s)

                    self._status[STATS.client_to_tunnel_idx] += 1
                    p = tunnel_packet_pack(
                        'x'.encode(), PacketHeader.session_create,
                        listen_port_info[0], client_port, listen_port_info[2])
                    tunnel_tx_queue.append(p)
                    self.set_pending_write(self._tunnel_sock)

                    logging.info(
                        "Forward client -> tunnel session %s %s:%d => %s:%d start!",
                        "tcp" if listen_port_info[0] == socket.SOCK_STREAM else "udp",
                        la[0], la[1], ra[0], ra[1])
                elif fid in clients_fds:
                    if len(tunnel_tx_queue) >= 512:
                        # 避免发送累积过多处理不及时，导致整体性能低
                        continue

                    info = clients_fds[fid]
                    try:
                        data = sock.recv(STATS.MTU)
                    except (TimeoutError, ConnectionResetError):
                        logging.info(
                            "Client\n%s", traceback.format_exc())
                        data = None

                    if not data:
                        p = tunnel_packet_pack(
                            'x'.encode(), PacketHeader.session_destroy,
                            info[2], info[3], info[4])
                        tunnel_tx_queue.append(p)

                        close_client(sock)

                        # 避免后续发送轮询失败
                        if sock in w:
                            w.remove(sock)
                    else:
                        p = tunnel_packet_pack(
                            data, PacketHeader.data,
                            info[2], info[3], info[4])
                        tunnel_tx_queue.append(p)
                        _pkts, _bytes = self.flush_tx(
                            tunnel_tx_queue, self._tunnel_sock)
                        self._tx_rate.feed(now, _bytes, _pkts)
                    self.set_pending_write(self._tunnel_sock)
                else:
                    raise Exception("Unknow RX socket!", sock)

            if self._terminate:
                break

            for sock in list(w):
                fid = sock.fileno()
                assert fid != -1

                if sock == self._tunnel_sock:
                    _pkts, _bytes = self.flush_tx(tunnel_tx_queue, sock)
                    self._tx_rate.feed(now, _bytes, _pkts)

                    if _pkts:
                        logging.debug(
                            "Tunnel TX pkts:%d bytes:%d cache num:%d",
                            _pkts, _bytes, len(tunnel_tx_queue))

                    if tunnel_tx_queue:
                        self.set_pending_write(sock)
                elif fid in clients_fds:
                    info = clients_fds[fid]
                    tx_queue = info[1]
                    _pkts, _bytes = self.flush_tx(tx_queue, sock)
                    self._status[STATS.rx_cache_idx] -= _pkts
                    if _pkts:
                        logging.debug(
                            "TX client pkts:%d bytes:%d tx cache num:%d",
                            _pkts, _bytes, len(tx_queue))
                    if tx_queue:
                        self.set_pending_write(sock)
                else:
                    raise Exception("Unknow TX socket!", sock)

            # 每隔1s更新一次计数
            if now - stats_last_update_time > 1:
                self._status[STATS.tx_cache_idx] = len(tunnel_tx_queue)
                stats_last_update_time = now

            if tunnel_tx_queue:
                self.set_pending_write(self._tunnel_sock)
                pass

            if self._status[STATS.rx_cache_idx] > 0:
                for k, v in clients_fds.items():
                    tx_queue = v[1]
                    if tx_queue:
                        self.set_pending_write(v[0])

    def main_proc(self):
        try:
            self.do_main_proc()
        except:
            logging.error(
                "Port Forward worker exit\n(%s)",
                traceback.format_exc())

        self._tunnel_sock.close()
        for _, m in self._port_maps.items():
            m[0].close()

        del STATS.workers[self.id()]
        logging.info("Forward Worker exit!")


class PortForwardBase(object):
    def __init__(self, port_map_conf):
        '''
        port-map: 
            (tcp/udp, local port, remote port)
        port_map_conf: 
            [
                <local map conf>[port-map],
                <remote map conf>[port-map],
            ]
        '''
        self._threads = []
        self._port_map_conf = port_map_conf
        self._workers = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        assert self._sock.fileno() == -1
        logging.debug("Port Forward closing!")
        for w in self._workers:
            w.terminate()

        for t in self._threads:
            t.join(timeout=5)

        self._workers = []
        logging.info("Port Forward closed!")

    def _start_thread(self, func, param):
        t = threading.Thread(target=func, args=param)
        t.daemon = True
        t.start()
        self._threads.append(t)
        return t


class PortForwardServer(PortForwardBase):
    def __init__(
            self, tunnel_addr, port_map_conf, server_key=None):
        PortForwardBase.__init__(self, port_map_conf)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(tunnel_addr)
        self._sock.listen(10)
        self._server_key = server_key

    def __gen_challenge(self):
        s = str(time.time()).encode()
        return hashlib.md5(s).hexdigest()[:16]

    def __start_worker(self, sock):
        worker = PortForwardWorker(sock)
        if not worker.setup_map_sock(self._port_map_conf[0]):
            return False

        if self._port_map_conf[1]:
            # send request port map config
            content = json.dumps(
                self._port_map_conf[1]).encode()
            d = tunnel_packet_pack(
                content, PacketHeader.port_map, 0, 0, 0)
            n = sock.send(d)
            assert n == len(d)

        self._workers.append(worker)
        self._start_thread(worker.main_proc, ())

        return True

    def run(self):
        rs = [self._sock]
        unauth_client = {}
        while True:
            try:
                _e = None
                now = time.time()
                clients = [v[0] for _, v in unauth_client.items()]
                r, _, _ = select.select(rs + clients, [], [], 10)

                if not r:
                    for c in clients:
                        info = unauth_client[c.fileno()]
                        la = info[2]
                        ra = info[3]

                        del unauth_client[c.fileno()]
                        c.close()
                        logging.error(
                            "Port Forward Client: %s:%d => %s:%d auth timeout!\n%s",
                            la[0], la[1], ra[0], ra[1],
                            traceback.format_exc())

                if self._sock in r:
                    c, ra = self._sock.accept()
                    assert (r.index(self._sock) == 0)
                    del r[0]
                    try:
                        # set tcp keepalive
                        utils.set_keep_alive(c)
                        la = c.getsockname()

                        if self._server_key:
                            challenge = self.__gen_challenge()
                            content = {
                                "challenge": challenge,
                                "action": "auth-init"
                            }
                            c.send(json.dumps(content).encode())
                            unauth_client[c.fileno()] = [
                                c, challenge, la, ra, now]
                            logging.info(
                                "Forward Tunnel Client: %s:%d => %s:%d auth start!",
                                la[0], la[1], ra[0], ra[1])
                        else:
                            if not self.__start_worker(c):
                                raise Exception(
                                    "Client:%s:%d => %s:%d start failed!",
                                    la[0], la[1], ra[0], ra[1])
                            logging.info(
                                "Forward Tunnel Client: %s:%d => %s:%d opened!",
                                la[0], la[1], ra[0], ra[1])
                    except:
                        c.close()
                        logging.error(
                            "Port Forward Client initing failed\n%s",
                            traceback.format_exc())

                for c in r:
                    assert (self._server_key != None)
                    info = unauth_client[c.fileno()]
                    assert (c == info[0])
                    challenge = info[1]
                    la = info[2]
                    ra = info[3]
                    try:
                        d = c.recv(2048)
                        if not d:
                            raise Exception(
                                "Client:%s:%d => %s:%d sock closed",
                                la[0], la[1], ra[0], ra[1])

                        info = json.loads(d.decode())
                        if type(info) != dict or "auth" not in info:
                            raise Exception(
                                "Client:%s:%d => %s:%d auth msg missing!",
                                la[0], la[1], ra[0], ra[1])

                        auth = hashlib.md5(
                            (challenge + self._server_key).encode()).hexdigest()[:16]
                        if info["auth"] != auth:
                            c.send(json.dumps(
                                {"action": "auth-faild"}).encode())
                            raise Exception(
                                "Client:%s:%d => %s:%d auth failed!",
                                la[0], la[1], ra[0], ra[1])

                        c.send(json.dumps({"action": "auth-ok"}).encode())
                        logging.info(
                            "Forward Tunnel Client: %s:%d => %s:%d auth success!",
                            la[0], la[1], ra[0], ra[1])

                        if not self.__start_worker(c):
                            raise Exception(
                                "Client:%s:%d => %s:%d start failed!",
                                la[0], la[1], ra[0], ra[1])

                        del unauth_client[c.fileno()]
                    except:
                        del unauth_client[c.fileno()]
                        c.close()
                        logging.error("Forward Tunnel created faild!\n%s",
                                      traceback.format_exc())

            except KeyboardInterrupt:
                self._sock.close()
                _e = UserAbort()
            except Exception as e:
                self._sock.close()
                _e = e
            finally:
                if _e:
                    raise _e


class PortForwardClient(PortForwardBase):
    def __init__(
            self, tunnel_addr, port_map_conf, server_key=None):
        PortForwardBase.__init__(self, port_map_conf)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.connect(tunnel_addr)
        self._server_key = server_key

    def __do_auth(self):
        challenge = None
        la = self._sock.getsockname()
        ra = self._sock.getpeername()
        rs = [self._sock]
        ws = []

        logging.info(
            "Forward Tunnel Client: %s:%d => %s:%d auth start!",
            la[0], la[1], ra[0], ra[1])
        while True:
            r, w, _ = select.select(rs, ws, [], 10)
            ws = []
            if r:
                d = self._sock.recv(2048)
                if not d:
                    raise Exception(
                        "Client Forward session: %s:%d => %s:%d closed",
                        la[0], la[1], ra[0], ra[1])

                info = json.loads(d.decode())
                if type(info) != dict or "action" not in info:
                    raise Exception(
                        "Client:%s:%d => %s:%d auth msg missing!",
                        la[0], la[1], ra[0], ra[1])

                action = info["action"]
                if action == "auth-init":
                    if "challenge" not in info:
                        raise Exception(
                            "Client:%s:%d => %s:%d auth msg(%s) format error!",
                            la[0], la[1], ra[0], ra[1], json.dumps(info))

                    challenge = info["challenge"]
                    ws.append(self._sock)
                elif action == "auth-ok":
                    logging.info(
                        "Forward Tunnel Client: %s:%d => %s:%d auth success!",
                        la[0], la[1], ra[0], ra[1])
                    return
                elif action == "auth-faild":
                    logging.info(
                        "Forward Tunnel Client: %s:%d => %s:%d auth faild!",
                        la[0], la[1], ra[0], ra[1])
                    raise AuthFailed()
            if w:
                if challenge:
                    auth = hashlib.md5(
                        (challenge + self._server_key).encode()
                    ).hexdigest()[:16]
                    self._sock.send(json.dumps({"auth": auth}).encode())

            if not r and not w:
                logging.info(
                    "Forward Tunnel Client: %s:%d => %s:%d auth timeout!",
                    la[0], la[1], ra[0], ra[1])
                raise AuthFailed()

    def run(self):
        worker = None
        try:
            _e = None
            utils.set_keep_alive(self._sock)

            la = self._sock.getsockname()
            ra = self._sock.getpeername()

            if self._server_key:
                self.__do_auth()

            # set tcp keepalive
            utils.set_keep_alive(self._sock)
            logging.info(
                "Client Forward session: %s:%d => %s:%d opened!",
                la[0], la[1], ra[0], ra[1])

            worker = PortForwardWorker(self._sock)
            if not worker.setup_map_sock(self._port_map_conf[0]):
                self._sock.close()
                return

            if self._port_map_conf[1]:
                # send request port map config
                content = json.dumps(self._port_map_conf[1]).encode()
                d = tunnel_packet_pack(content, PacketHeader.port_map, 0, 0, 0)
                n = self._sock.send(d)
                assert n == len(d)

            self._workers.append(worker)
            worker.main_proc()
        except KeyboardInterrupt:
            self._sock.close()
            _e = UserAbort()
        except Exception as e:
            self._sock.close()
            _e = e
        finally:
            if _e:
                raise _e


if __name__ == '__main__':
    args = parse_args()
    set_loggint_format(args.verbose)

    params = (
        (args.ip, args.port),
        (args.local_port_map, args.remote_port_map),
        args.server_key
    )

    terminate = False
    status_thread = None

    def status_proc():
        start = time.time()
        last_time = start
        while not terminate:
            time.sleep(1)
            now = time.time()
            if now - last_time < args.status_period:
                continue

            last_time = now
            STATS.status(now - start)

        logging.info("status thread exit!")

    if args.show_status:
        status_thread = threading.Thread(target=status_proc, args=())
        status_thread.daemon = True
        status_thread.start()

    fail_try_time = 0
    wait_time = 5
    #
    # 12小时内不恢复，则退出
    #
    while fail_try_time < 3600*12/wait_time:
        normal_exit = False
        try:
            t = time.time()
            if args.is_tunnel_server:
                with PortForwardServer(*params) as f:
                    f.run()
            else:
                with PortForwardClient(*params) as f:
                    f.run()

            if time.time() - t > 5:
                normal_exit = True
                # 恢复计数
                fail_try_time = 0
        except (socket.gaierror, OSError) as e:
            logging.warning(
                "Port Forward instance exit\n(%s)",
                traceback.format_exc())
        except TunnelOffline:
            logging.info(
                "Tunnel offline\n(%s)",
                traceback.format_exc())
        except AuthFailed as e:
            logging.warning(
                "Port Forward Auth failed!")
            exit(1)
        except UserAbort as e:
            logging.warning(
                "Port Forward abort")
            exit(1)
        except AssertionError:
            logging.error(
                "Port Forward fatal error!\n(%s)",
                traceback.format_exc())
            exit(1)
        except Exception as e:
            logging.error(
                "Port Forward instance exit\n(%s)",
                traceback.format_exc())

        if not normal_exit:
            if fail_try_time * wait_time > 1800:
                # 超过30分钟不恢复，恢复计数重试
                fail_try_time = 0
            else:
                fail_try_time += 1

        # 避免无限失败请求
        time.sleep((fail_try_time + 1) * wait_time)

        STATS.restart_times += 1

    terminate = True
    if status_thread:
        status_thread.join(timeout=5)
    logging.info("Port Forward service exit!")
