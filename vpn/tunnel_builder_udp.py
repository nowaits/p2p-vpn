import socket
import time
import json
import select
import logging
import hashlib
import random
import traceback

import libs


def build_port_map(port, r):
    return list(range(port, min(port + r, 65536)))


def nat_tunnel_build_udp(conf, token, request_forward=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    s.bind(("0.0.0.0", 0))  # 绑定一个本地地址和随机端口
    local = s.getsockname()
    timeout = conf.timeout
    if request_forward:
        timeout = min(timeout, 30)

    # 1. get peer addr
    peer_public_addr = None
    public_addr = None
    start_time = time.time()
    do_forward = False

    ws = [s]
    while not peer_public_addr:
        r, w, _ = select.select([s], ws, [], 0.5)
        ws = []

        if s in r:
            data, addr = s.recvfrom(2048)
            try:
                if addr[0] != conf.server_ip or addr[1] != conf.port:
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
                    "UDP Forward %stunnel %s:%d=>%s:%d ok",
                    "(peer request) " if not request_forward else "",
                    public_addr[0], public_addr[1], peer_public_addr[0], peer_public_addr[1])
                s.connect((conf.server_ip, conf.port))
                return s

        if s in w:
            content = {
                "user": conf.user,
                "instance_id": conf.instance_id,
                "token": token,
                "action": "peer-info" if not request_forward else "request-forward",
            }
            s.sendto(json.dumps(content).encode(), (conf.server_ip, conf.port))

        if time.time() - start_time > timeout:
            logging.error("Get peer info timeout(%ds)", timeout)
            s.close()
            return None

        if not r and not w:
            ws.append(s)

    # 2. build tunnel
    logging.info(
        f"Try to build UDP tunnel {local[0]}:{local[1]}=>{peer_public_addr[0]}:{peer_public_addr[1]}")

    peer_ports = build_port_map(peer_public_addr[1], conf.port_try_range)
    offset = 0
    try_times = 0
    start_time = time.time()
    ws = [s]
    select_timeout = 0.1
    send_tag = hashlib.md5(
        (conf.user + peer_public_addr[0]).encode()).hexdigest()[:16]
    recv_tag = hashlib.md5(
        (conf.user + public_addr[0]).encode()).hexdigest()[:16]

    recv_req_ok = False
    ack_time = 10  # 收到req之后继续再发送10次，确保对方能收到resp消息
    while True:
        r, w, _ = select.select([s], ws, [], select_timeout)
        ws = []

        if s in w:
            if not recv_req_ok:
                try_times += 1
                l = int(32 * random.random() + 1)

                content = libs.packet_pack(
                    (send_tag + ":nat-req:" + libs.random_str(l)).encode(),
                    libs.PacketHeader.control)
                s.sendto(
                    content, (peer_public_addr[0], peer_ports[offset]))
                offset += 1
                if offset == len(peer_ports):
                    offset = 0
            else:
                l = int(32 * random.random() + 1)
                content = libs.packet_pack(
                    (send_tag + ":nat-resp:" + libs.random_str(l)).encode(),
                    libs.PacketHeader.control)
                s.send(content)
                ack_time -= 1
                if ack_time == 0:
                    logging.info(f"UDP Tunnel ok! peer:{addr[0]}:{addr[1]}")
                    return s

        if s in r:
            d, addr = s.recvfrom(2048)
            try:
                t, p, left = libs.packet_unpack(d)
                assert not left

                if t == libs.PacketHeader.control:
                    ds = p.decode().split(":")
                    if len(ds) == 3 and ds[0] == recv_tag and addr[0] == peer_public_addr[0]:
                        s.connect(addr)
                        if ds[1] == "nat-req":
                            recv_req_ok = True
                            logging.info(
                                f"UDP Tunnel req from {addr[0]}:{addr[1]} try times:{try_times}")
                        elif ds[1] == "nat-resp":
                            logging.info(
                                f"UDP Tunnel ok! peer:{addr[0]}:{addr[1]} try times:{try_times}")
                            return s
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

        if not r and not w:
            ws.append(s)

        if time.time() - start_time > timeout:
            logging.error(f"Build udp tunnel timeout!(try times:{try_times})")
            break
    s.close()
    return None
