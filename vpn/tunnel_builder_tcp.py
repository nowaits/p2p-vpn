import socket
import time
import json
import select
import logging
import errno
import random
import sys
import hashlib
import traceback

import libs


def create_tcp_sock():
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, True)
    libs.set_keep_alive(soc, after_idle=30, interval=30, max_fails=10)
    if not sys.platform.startswith("win"):
        pass

    return soc


def build_port_map(port, r):
    return list(range(port, min(port + r, 65536)))


def nat_tunnel_build_tcp(conf, token, request_forward=False):
    # 0. connect vpn server
    logging.info("connecting vpn server...")
    try_time = 5
    for t in range(try_time):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(5)
            s.connect((conf.server_ip, conf.port))
            break
        except BlockingIOError as e:
            if e.errno != errno.EINPROGRESS and e.errno != errno.WSAEWOULDBLOCK:
                s.close()
                s = None
                raise
        except socket.timeout as e:
            logging.warning(
                f"connect {(conf.server_ip, conf.port)} {t + 1}/{try_time} timeout")
            s.close()
            s = None

    if not s:
        return None

    s.setblocking(False)
    timeout = conf.timeout
    if request_forward:
        timeout = min(timeout, 30)

    # 1. get peer addr
    logging.info("get peer addr...")
    peer_public_addr = None
    public_addr = None
    start_time = time.time()
    do_forward = False

    ws = [s]
    recv_left = b''
    while not peer_public_addr:
        r, w, _ = select.select([s], ws, [], 0.5)
        ws = []

        if s in r:
            valid, d = libs.socket_recv(s)
            if not valid:
                s.close()
                logging.info(f"connecting server failed!")
                return None

            ok, ps, recv_left = \
                libs.packet_unpack_all(recv_left + d)
            if not ok:
                raise Exception("VPN Packet stream error!")

            for t, p in ps:
                if t != libs.PacketHeader.control:
                    logging.warning(f"unknown message: {t} - {p}")
                    continue

                try:
                    info = json.loads(p.decode())
                    if type(info) != dict:
                        logging.error(
                            "Resp:%s from server invalid!", str(info))
                        continue
                except Exception as e:
                    logging.error("Decode %s error(%s)", str(p), str(e))
                    continue

                logging.debug("Resp:%s from server", str(info))
                key_missing = False
                for k in ["peer-public-addr", "public-addr", "request-forward"]:
                    if k not in info:
                        key_missing = True
                        logging.error("Resp:%s missing key:%s!", str(info), k)
                        break

                if key_missing:
                    continue

                peer_public_addr = info["peer-public-addr"]
                public_addr = info["public-addr"]
                do_forward = info["request-forward"]
                if not do_forward:
                    logging.info(
                        "Get addr %s:%d=>%s:%d ok",
                        public_addr[0], public_addr[1], peer_public_addr[0], peer_public_addr[1])
                else:
                    logging.info(
                        "TCP Forward %stunnel %s:%d=>%s:%d ok",
                        "(peer request) " if not request_forward else "",
                        public_addr[0], public_addr[1], peer_public_addr[0], peer_public_addr[1])
                    return s

        if s in w:
            content = json.dumps({
                "user": conf.user,
                "instance_id": conf.instance_id,
                "token": token,
                "action": "peer-info" if not request_forward else "request-forward",
            }).encode()
            d = libs.packet_pack(content, libs.PacketHeader.control)
            ok, left = libs.socket_send(s, d)
            if not ok:
                logging.warning(f"peer closed\n{content}")
                return None

            assert not left

        if time.time() - start_time > timeout:
            logging.error("Get peer info timeout(%ds)", timeout)
            s.close()
            return None

        if not r and not w:
            ws = [s]

    s.close()

    # 2. prepare socket
    logging.info(
        "Try to build TCP tunnel to %s:%d...",
        peer_public_addr[0], peer_public_addr[1]
    )

    peer_ports = build_port_map(peer_public_addr[1], conf.port_try_range)
    ss = []
    sock_info = {}
    for p in peer_ports:
        s = create_tcp_sock()
        s.setblocking(False)

        try:
            s.connect((peer_public_addr[0], p))
        except BlockingIOError as e:
            if e.errno != errno.EINPROGRESS and e.errno != errno.WSAEWOULDBLOCK:
                s.close()
                raise

        ss.append(s)
        sock_info[s.fileno()] = {
            "tx": time.time(),
            "rx-left": b'', "rx-state": "init"
        }

    last_time = time.time()
    select_timeout = 0.1
    send_tag = hashlib.md5(
        (conf.user + peer_public_addr[0]).encode()).hexdigest()[:16]
    recv_tag = hashlib.md5(
        (conf.user + public_addr[0]).encode()).hexdigest()[:16]

    tunnel_sock = None

    def sock_cleanup():
        for s in ss:
            if s != tunnel_sock:
                s.close()
            ss.remove(s)

    # 3. build tunnel
    logging.info("start building...")
    #
    # @note: 可能同时协商出多个隧道
    #
    #   出现多个隧道时，会选中第一个回复的tunnel，两端如果选择不是同一个
    #   会话，可能导致隧道被释放，本次协商失败
    #
    while not tunnel_sock and len(ss):
        r, w, _ = select.select(ss, ss, [], select_timeout)

        now = time.time()
        if now - last_time > 5:
            break

        for s in w:
            i = sock_info[s.fileno()]
            if now - i["tx"] < 0.1:
                continue

            i["tx"] = now
            try:
                l = int(32 * random.random() + 1)
                if i["rx-state"] == "init":
                    tag = "nat-req"
                else:
                    tag = "nat-resp"
                content = send_tag + ":" + tag + ":" + libs.random_str(l)
                s.send(libs.packet_pack(
                    content.encode(),
                    libs.PacketHeader.control))

                if i["rx-state"] == "nat-resp":
                    tunnel_sock = s
                    break
            except Exception as e:
                logging.warning("error=\n(%s)", traceback.format_exc())
                ss.remove(s)
                s.close()

        if tunnel_sock:
            break

        for s in r:
            if s not in ss:
                continue

            i = sock_info[s.fileno()]

            try:
                d = s.recv(2048)
                if not d:
                    ss.remove(s)
                    s.close()
                    break

                ok, ps, i["rx-left"] = \
                    libs.packet_unpack_all(i["rx-left"] + d)
                if not ok:
                    raise Exception("VPN Packet stream error!")

                for t, p in ps:
                    if t == libs.PacketHeader.control:
                        ds = p.decode().split(":")
                        if len(ds) == 3 and ds[0] == recv_tag:
                            remote_addr = s.getpeername()
                            last_time = now  # 更新超时时间

                            if ds[1] == "nat-req":
                                if i["rx-state"] == "init":
                                    i["rx-state"] = ds[1]
                                logging.info(
                                    f"TCP Tunnel req from {remote_addr[0]}:{remote_addr[1]}")
                            elif ds[1] == "nat-resp":
                                i["rx-state"] = ds[1]
                                logging.info(
                                    f"TCP Tunnel ok! peer:{remote_addr[0]}:{remote_addr[1]}")
                            else:
                                logging.warning(f"Unknow tunnel msg: {p}")
                        else:
                            logging.warning(f"Invalid control msg: {p}")
                    elif t < libs.PacketHeader.invalid_type:
                        logging.debug(f"skip tunnel packet:{t} {p}")
                    else:
                        logging.warning(f"Invalid packet:{t} {p}")
            except Exception:
                logging.warning("error=\n(%s)", traceback.format_exc())
                pass

        if not r:
            t = random.random() / 5
            select_timeout = t

    sock_cleanup()
    return tunnel_sock
