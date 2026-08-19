import sys
import select
import time
import logging
import json
import hashlib
import hmac
import libs

assert sys.version_info >= (3, 6)


class VPNServer(object):
    def __init__(self, tcp_sock, udp_sock, server_key):
        self._tcp_sock = tcp_sock
        self._udp_sock = udp_sock
        self._server_key = server_key
        self._client_record_timeout = 30
        '''
        {
            "user0": {
                "instance": {
                    "f5b472de8c4bcc16": {
                        "public-addr": "39.148.225.26",
                        "public-port": 45626,
                        "time": 1787020683.5010393,
                        "id": "f5b472de8c4bcc16"
                    },
                    "f6acb3fb07763e1f": {
                        "public-addr": "202.111.152.10",
                        "public-port": 34611,
                        "time": 1787020683.005857,
                        "id": "f6acb3fb07763e1f"
                    }
                },
                "token": "e92759dfe4ee0ca8",
                "time": 1787020652.9997785
            }
        }
        '''
        self._udp_clients = {}
        '''
        {
            "user0": {
                "instance": {
                    "f5b472de8c4bcc16": {
                        "local-soc-fd": 3,
                        "peer-soc-fd": 4,
                        "public-addr": "39.148.225.26",
                        "public-port": 45626,
                        "time": 1787020683.5010393,
                        "id": "f5b472de8c4bcc16"
                    },
                    "f6acb3fb07763e1f": {
                        "local-soc-fd": 4,
                        "peer-soc-fd": 3,
                        "public-addr": "202.111.152.10",
                        "public-port": 34611,
                        "time": 1787020683.005857,
                        "id": "f6acb3fb07763e1f"
                    }
                },
                "token": "e92759dfe4ee0ca8",
                "time": 1787020652.9997785
            }
        }
        '''
        self._tcp_clients = {}
        '''
        {
            "202.111.152.10:34611": {
                "peer-addr": "39.148.225.26",
                "peer-port": 45626,
                "peer-ready": true,
                "time": 1787020683.5010393
            },
            "39.148.225.26:45626": {
                "peer-addr": "202.111.152.10",
                "peer-port": 34611,
                "peer-ready": true,
                "time": 1787020683.5010393
            }
        }
        '''
        self._udp_forward_table = {}
        '''
        {
            "3": {
                "peer-addr": "39.148.225.26",
                "peer-port": 45626,
                "peer-soc-fd": 4
            },
            "4": {
                "peer-addr": "202.111.152.10",
                "peer-port": 34611,
                "peer-soc-fd": 3
            }
        }
        '''
        self._tcp_forward_table = {}
        '''
        {
            "user0": {
                "instance": {
                    "f5b472de8c4bcc16": {
                        "public-addr": "39.148.225.26",
                        "public-port": 45626,
                        "time": 1787016962.6058931,
                        "auth": "7a72dc3a5b06eeac",
                        "local-addr": ["10.220.21.45", 32452],
                        "local-ipv4": [
                            ["192.168.20.240", 24],
                            ["10.220.21.45", 24],
                            ["10.0.3.1", 24],
                            ["172.17.0.1", 16],
                            ["172.18.0.1", 16],
                            ["20.0.0.10", 24]
                        ]
                    },
                    "f6acb3fb07763e1f": {
                        "public-addr": "202.111.152.10",
                        "public-port": 34611,
                        "time": 1787016964.265457,
                        "auth": "7a72dc3a5b06eeac",
                        "local-addr": ["192.168.31.211", 32452],
                        "local-ipv4": [
                            ["192.168.31.211", 24],
                            ["192.168.31.221", 24],
                            ["10.0.3.1", 24],
                            ["172.17.0.1", 16],
                            ["172.26.0.1", 16],
                            ["172.24.0.1", 16],
                            ["20.0.0.2", 24]
                        ]
                    }
                },
                "challenge": "39dc26308a4d603f",
                "time": 1787016962.6058931
            }
        }
        '''
        self._clients_waiting = {}
        self._rx_socks = []
        self._tx_socks = []
        '''
        {
            "3": {
                "public-addr": ["10.0.0.200", 32452],
                "data": {
                    "rx-left": b'',
                    "tx-left": b'',
                },
                "sock": <client socket>
            }
        }
        '''
        self._sock_info = {}

    def __gen_challenge(self, now):
        return hashlib.md5(str(now).encode()).hexdigest()[:16]

    def __do_server_auth(self, addr, info, now):
        '''
        1. 当有一端用户接入时
            1. 验证客户端密钥
            2. 定期刷新challenge
        2. 当p2p两端同时接入时
            1. 生成p2p会话唯一token
            2. 通知两端开启接入流程
        '''
        user = info["user"]
        instance_id = info["instance_id"]

        if user not in self._clients_waiting:
            self._clients_waiting[user] = {"instance": {}, "time": now}
        client_waiting = self._clients_waiting[user]
        instance = client_waiting["instance"]

        # 每隔1分钟自动更新challenge
        challenge_update = False
        if "challenge" not in client_waiting or \
                now - client_waiting["time"] > 60:
            client_waiting["challenge"] = self.__gen_challenge(now)
            client_waiting["time"] = now
            challenge_update = True

        if challenge_update or "auth" not in info:
            self._udp_sock.sendto(json.dumps({
                "action": "challenge",
                "challenge": client_waiting["challenge"]
            }).encode(), addr)
            return

        for k in ["local-addr", "local-ipv4"]:
            if k not in info:
                logging.info(f"Recv data: {str(info)} missing key:{k}")
                return

        local = {
            "local-addr": info["local-addr"],
            "local-ipv4": info["local-ipv4"],
            "public-addr": addr[0], "public-port": addr[1],
            "time": now, "auth": info["auth"]
        }
        instance[instance_id] = local

        # 1. remove timeout
        for _k, _v in list(instance.items()):
            if now - _v["time"] > 10:  # 10s超时
                del instance[_k]

        items = list(instance.items())
        if len(items) > 2:
            logging.error(
                "More then 2 client using same accout!(%s)", str(items))
            del self._clients_waiting[user]
            return

        # 服务器认证
        if self._server_key:
            if "server-auth" not in info:
                self._udp_sock.sendto(json.dumps({
                    "action": "server-auth-required"
                }).encode(), addr)
                logging.error(
                    "Client: %s instance: %s auth needed!", user, instance_id)
                del instance[instance_id]
                return
            server_auth = hmac.new(
                client_waiting["challenge"].encode(), self._server_key.encode(), digestmod='md5'
            ).hexdigest()[:16]
            if info["server-auth"] != server_auth:
                self._udp_sock.sendto(json.dumps({
                    "action": "server-auth-failed"
                }).encode(), addr)
                logging.error(
                    "Client: %s instance: %s auth failed!", user, instance_id)
                del instance[instance_id]
                return
        else:
            server_auth = hmac.new(
                client_waiting["challenge"].encode(), 'x'.encode(), digestmod='md5'
            ).hexdigest()[:16]

        if len(items) != 2:
            client_waiting["time"] = now
            return

        peer = items[1][1] if items[0][0] == instance_id else items[0][1]
        if peer["auth"] != info["auth"]:
            logging.info("Client: %s auth check failed!",
                         str(self._clients_waiting[user]))
            del self._clients_waiting[user]
            self._udp_sock.sendto(json.dumps({
                "action": "peer-auth-failed"
            }).encode(), addr)
            return

        del self._clients_waiting[user]
        token = hmac.new(
            info["auth"].encode(), server_auth.encode(), digestmod='md5'
        ).hexdigest()[:16]
        local_content = json.dumps({
            "action": "peer-ready",
            "token": token,
            "public-addr": [local["public-addr"], local["public-port"]],
            "peer-addr": [peer["public-addr"], peer["public-port"]],
            "peer-local": peer["local-addr"],
            "peer-ip4": peer["local-ipv4"]
        }).encode()
        peer_content = json.dumps({
            "action": "peer-ready",
            "token": token,
            "public-addr": [peer["public-addr"], peer["public-port"]],
            "peer-addr": [local["public-addr"], local["public-port"]],
            "peer-local": local["local-addr"],
            "peer-ip4": local["local-ipv4"]
        }).encode()

        self._udp_clients[user] = {"time": now, "instance": {}, "token": token}
        self._tcp_clients[user] = {"time": now, "instance": {}, "token": token}
        self._udp_sock.sendto(local_content, addr)
        self._udp_sock.sendto(
            peer_content, (peer["public-addr"], peer["public-port"]))

    def __checkout_timeout(self, now):
        for k in list(self._udp_clients.keys()):
            if now - self._udp_clients[k]["time"] > self._client_record_timeout:
                logging.info(
                    "Drop out-of-date user:%s info:%s", k, str(self._udp_clients[k]))
                del self._udp_clients[k]

        for k in list(self._tcp_clients.keys()):
            if now - self._tcp_clients[k]["time"] > self._client_record_timeout:
                logging.info(
                    "Drop out-of-date user:%s info:%s", k, str(self._tcp_clients[k]))
                del self._tcp_clients[k]

        for k in list(self._udp_forward_table.keys()):
            if k not in self._udp_forward_table:
                continue
            forward = self._udp_forward_table[k]
            if now - forward["time"] <= self._client_record_timeout:
                continue

            logging.info("Drop out-of-date forward:%s", k)
            del self._udp_forward_table[k]
            peer_k = "%s:%d" % (forward["peer-addr"], forward["peer-port"])
            if peer_k in self._udp_forward_table:
                logging.info("Drop out-of-date forward:%s", peer_k)
                del self._udp_forward_table[peer_k]

        for k in list(self._clients_waiting.keys()):
            if now - self._clients_waiting[k]["time"] > self._client_record_timeout:
                logging.info(
                    "Drop out-of-date user:%s waiting:%s", k, str(self._clients_waiting[k]))
                del self._clients_waiting[k]

    def __udp_rx_cb(self, now):
        data, addr = self._udp_sock.recvfrom(2048)

        # 1. just forward data
        k = "%s:%d" % (addr[0], addr[1])
        if k in self._udp_forward_table:
            forward = self._udp_forward_table[k]

            if not forward["peer-ready"]:
                logging.debug(
                    "Peer %s:%d not in forward table, drop msg:%s",
                    forward["peer-addr"], forward["peer-port"], str(data))
                return

            self._udp_sock.sendto(
                data, (forward["peer-addr"], forward["peer-port"]))
            forward["time"] = now
            return

        # 2. do check
        try:
            info = json.loads(data.decode())
        except Exception as e:
            logging.error(
                "Decode %s error(%s) addr:%s",
                str(data), str(e), k)
            return

        key_missing = False
        for _k in ["user", "action", "instance_id"]:
            if _k not in info:
                logging.debug("Recv data: %s format invalid", str(info))
                key_missing = True
                break
        if key_missing:
            return

        if info["action"] not in ["wait-peer", "peer-info", "request-forward"]:
            logging.debug("Unknow:%s method!", info["action"])
            return

        action = info["action"]
        user = info["user"]
        instance_id = info["instance_id"]

        logging.debug("Recv client=%s:%d user=%s action=%s",
                      addr[0], addr[1], user, action)

        # 3. do user verify
        if action == "wait-peer":
            self.__do_server_auth(addr, info, now)
            return

        # 4. exchange user info
        if user not in self._udp_clients:
            # 需要在__do_server_auth中完成初始化
            return

        client = self._udp_clients[user]

        if "token" not in info or client["token"] != info["token"]:
            #
            # 删除当前用户信息，需要用户重新协商
            #
            del self._udp_clients[user]
            return

        local = {
            "public-addr": addr[0], "public-port": addr[1],
            "time": now, "id": instance_id
        }
        client["instance"][instance_id] = local

        # 1. remove timeout
        for ins_id, ins in list(client["instance"].items()):
            if now - ins["time"] > 2:  # record out of date
                logging.info(
                    "Record: %s:%d out of date(%.2f)",
                    ins["public-addr"], ins["public-port"],
                    now - ins["time"]
                )
                del client["instance"][ins_id]

        items = list(client["instance"].items())
        if len(items) > 2:
            logging.error(
                "More then 2 client using same accout!(%s)", str(items))
            del self._udp_clients[user]
            return

        if len(items) != 2:
            client["time"] = now
            return

        peer = items[1][1] if items[0][0] == instance_id else items[0][1]

        # set forward table
        do_forward = False
        peer_k = "%s:%d" % (peer["public-addr"], peer["public-port"])
        if info["action"] == "request-forward" or \
                peer_k in self._udp_forward_table:
            do_forward = True
            logging.info(
                "add forward table: %s:%d => %s:%d",
                addr[0], addr[1], peer["public-addr"], peer["public-port"])

            if peer_k in self._udp_forward_table:
                assert self._udp_forward_table[peer_k]["peer-addr"] == addr[0]
                self._udp_forward_table[k] = {
                    "peer-addr": peer["public-addr"],
                    "peer-port": peer["public-port"],
                    "peer-ready": True,
                    "time": now,
                }
                self._udp_forward_table[peer_k] = {
                    "peer-addr": addr[0],
                    "peer-port": addr[1],
                    "peer-ready": True,
                    "time": now,
                }
                # NOTE: client记录已经无效，触发记录删除
                client["time"] -= self._client_record_timeout
            else:
                self._udp_forward_table[k] = {
                    "peer-addr": peer["public-addr"],
                    "peer-port": peer["public-port"],
                    "peer-ready": False,
                    "time": now,
                }

        # send peer info
        peer_info = json.dumps({
            "peer-public-addr": (peer["public-addr"], peer["public-port"]),
            "public-addr": (local["public-addr"], local["public-port"]),
            "request-forward": do_forward,
            "time": now,
        }).encode()
        local_info = json.dumps({
            "peer-public-addr": (local["public-addr"], local["public-port"]),
            "public-addr": (peer["public-addr"], peer["public-port"]),
            "request-forward": do_forward,
            "time": now,
        }).encode()
        self._udp_sock.sendto(
            peer_info, (local["public-addr"], local["public-port"]))
        self._udp_sock.sendto(
            local_info, (peer["public-addr"], peer["public-port"]))

    def __tcp_client_rx_cb(self, sock_info, t, p, now):
        addr = sock_info["public-addr"]
        fd = sock_info["sock"].fileno()

        try:
            assert t == libs.PacketHeader.control
            info = json.loads(p)
        except Exception as e:
            logging.error(
                "Decode %s error(%s) addr:%s",
                str(p), str(e), sock_info["public-addr"])
            return

        key_missing = False
        for _k in ["user", "action", "instance_id"]:
            if _k not in info:
                logging.debug("Recv data: %s format invalid", str(info))
                key_missing = True
                break
        if key_missing:
            return

        #
        # @note: wait-peer操作在UDP流程中完成，并生成token
        #
        if info["action"] not in ["peer-info", "request-forward"]:
            logging.debug("Unknow:%s method!", info["action"])
            return

        action = info["action"]
        user = info["user"]
        instance_id = info["instance_id"]

        logging.debug("Recv client=%s:%d user=%s action=%s",
                      addr[0], addr[1], user, action)

        # 0. exchange user info
        if user not in self._tcp_clients:
            # 需要在__do_server_auth中完成初始化
            return

        client = self._tcp_clients[user]

        if "token" not in info or client["token"] != info["token"]:
            #
            # 删除当前用户信息，需要用户重新协商
            #
            del self._tcp_clients[user]
            return

        local = {
            "local-soc-fd": fd,
            "public-addr": addr[0], "public-port": addr[1],
            "time": now, "id": instance_id
        }
        client["instance"][instance_id] = local

        # 1. remove timeout
        for ins_id, ins in list(client["instance"].items()):
            if now - ins["time"] > 2:  # record out of date
                logging.info(
                    "Record: %s:%d out of date(%.2f)",
                    ins["public-addr"], ins["public-port"],
                    now - ins["time"]
                )
                del client["instance"][ins_id]

        items = list(client["instance"].items())
        if len(items) > 2:
            logging.error(
                "More then 2 client using same accout!(%s)", str(items))
            del self._udp_clients[user]
            return

        if len(items) != 2:
            client["time"] = now
            return

        peer = items[1][1] if items[0][0] == instance_id else items[0][1]

        if peer["local-soc-fd"] not in self._sock_info:
            # 对方socket已经无效
            client["time"] = now
            del client["instance"][ins_id]
            return

        local["peer-soc-fd"] = peer["local-soc-fd"]
        peer["peer-soc-fd"] = local["local-soc-fd"]

        # set forward table
        do_forward = False
        peer_fd = local["peer-soc-fd"]
        if info["action"] == "request-forward" or \
                peer_fd in self._tcp_forward_table:
            do_forward = True
            self._tcp_forward_table[fd] = {
                "peer-addr": peer["public-addr"],
                "peer-port": peer["public-port"],
                "peer-soc-fd": peer_fd,
            }
            self._tcp_forward_table[peer_fd] = {
                "peer-addr": local["public-addr"],
                "peer-port": local["public-port"],
                "peer-soc-fd": fd,
            }
            logging.info(
                "tcp forward %s:%d <=> %s:%d add",
                local["public-addr"], local["public-port"],
                peer["public-addr"], peer["public-port"],
            )

        # setup peer info
        peer_info = json.dumps({
            "peer-public-addr": (peer["public-addr"], peer["public-port"]),
            "public-addr": (local["public-addr"], local["public-port"]),
            "request-forward": do_forward,
            "time": now,
        }).encode()
        local_info = json.dumps({
            "peer-public-addr": (local["public-addr"], local["public-port"]),
            "public-addr": (peer["public-addr"], peer["public-port"]),
            "request-forward": do_forward,
            "time": now,
        }).encode()

        peer_sock_info = self._sock_info[local["peer-soc-fd"]]

        sock_info["data"]["tx-left"] += libs.packet_pack(
            peer_info, libs.PacketHeader.control)
        peer_sock_info["data"]["tx-left"] += libs.packet_pack(
            local_info, libs.PacketHeader.control)

    def __remove_client_socket(self, s, peer_sock_remove_cb):
        fd = s.fileno()
        assert fd in self._sock_info
        assert s in self._rx_socks

        sock_info = self._sock_info[fd]

        logging.info(f"socket {sock_info["public-addr"]}: remove")
        if fd in self._tcp_forward_table:
            #
            # tcp转发会话断开，释放转发隧道
            #
            forward = self._tcp_forward_table[fd]
            peer_fd = forward["peer-soc-fd"]
            assert peer_fd in self._sock_info

            peer_sock = self._sock_info[peer_fd]["sock"]

            peer_sock_remove_cb(peer_sock)

            assert peer_sock in self._rx_socks
            self._rx_socks.remove(peer_sock)

            del self._tcp_forward_table[fd]
            del self._tcp_forward_table[peer_fd]
            del self._sock_info[peer_fd]

            peer_sock.close()

            logging.info(
                "tcp forward %s:%d <=> %s:%d remove",
                sock_info["public-addr"][0],
                sock_info["public-addr"][1],
                forward["peer-addr"], forward["peer-port"]
            )

        self._rx_socks.remove(s)
        del self._sock_info[fd]
        s.close()

    def run(self):
        tla = self._tcp_sock.getsockname()
        ula = self._udp_sock.getsockname()
        last_timeout_check = time.time()
        logging.info(
            f"VPN Server start on tcp={tla[0]}:{tla[1]} udp={ula[0]}:{ula[1]}"
        )

        self._rx_socks = [self._tcp_sock, self._udp_sock]
        self._tx_socks = []
        while True:
            #
            # udp: 一个listener
            # tcp：一个llistener + 多个client
            #
            r, w, _ = select.select(self._rx_socks, self._tx_socks, [], 10)
            self._tx_socks = []
            now = time.time()

            if now > last_timeout_check + 10:
                self.__checkout_timeout(now)
                last_timeout_check = now

            for s in r:
                if s == self._udp_sock:
                    self.__udp_rx_cb(now)
                elif s == self._tcp_sock:
                    cs, addr = self._tcp_sock.accept()
                    cs.setblocking(False)

                    self._sock_info[cs.fileno()] = {
                        "public-addr": addr,
                        "data": {
                            "rx-left": b'',
                            "tx-left": b'',
                        },
                        "sock": cs
                    }
                    self._rx_socks.append(cs)
                    logging.info(f"tcp client: {addr}")
                else:
                    # tcp client
                    fd = s.fileno()
                    assert fd in self._sock_info
                    valid, d = libs.socket_recv(s)
                    sock_info = self._sock_info[fd]

                    if not valid:
                        self.__remove_client_socket(
                            s, lambda peer_sock: libs.saferemove(w, peer_sock))
                        libs.saferemove(w, s)
                        continue

                    if fd in self._tcp_forward_table:
                        forward = self._tcp_forward_table[fd]
                        forward_fd = forward["peer-soc-fd"]
                        assert forward_fd in self._sock_info
                        self._sock_info[forward_fd]["data"]["tx-left"] += d
                        continue

                    ok, ps, sock_info["data"]["rx-left"] = \
                        libs.packet_unpack_all(
                            sock_info["data"]["rx-left"] + d)
                    if not ok:
                        logging.warning(f"packet format error {d}")
                        self.__remove_client_socket(
                            s, lambda peer_sock: libs.saferemove(w, peer_sock))
                        libs.saferemove(w, s)
                        continue
                    for t, p in ps:
                        self.__tcp_client_rx_cb(sock_info, t, p, now)

            for s in w:
                fd = s.fileno()
                if fd not in self._sock_info:
                    continue

                sock_info = self._sock_info[fd]
                if sock_info["data"]["tx-left"]:
                    ok, left = libs.socket_send(
                        s, sock_info["data"]["tx-left"])
                    if not ok:
                        logging.warning(f"socket send error {sock_info["data"]["tx-left"]}")
                    sock_info["data"]["tx-left"] = left

            for _, sock_info in self._sock_info.items():
                if len(sock_info["data"]["tx-left"]):
                    self._tx_socks.append(sock_info["sock"])
