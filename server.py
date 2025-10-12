import os
import sys
import socket
import select
import time
import logging
import argparse
import json
import hashlib
import hmac

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
    parser = argparse.ArgumentParser(description="server")
    parser.add_argument(
        "--port", "-p", type=int,
        default=5100, help="server port, default 5100")
    parser.add_argument(
        "--server-key", type=str, default=None, help="server authentication key")
    parser.add_argument(
        '--verbose', "-v", default=LOG_CHOICES[2], choices=LOG_CHOICES, help="log level")
    parser.add_argument(
        "--logfile", type=str, default=None,
        help="if set, then running log redirect to file")
    return parser.parse_args()


class VPNRelay(object):
    def __init__(self, sock, server_key):
        self._sock = sock
        self._clients = {}
        self._server_key = server_key
        self._forward_table = {}
        self._clients_waiting = {}
        self._client_record_timeout = 30

    def __gen_challenge(self, now):
        return hashlib.md5(str(now).encode()).hexdigest()[:16]

    def __do_auth(self, s, addr, info, now):
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
            s.sendto(json.dumps({
                "action": "challenge",
                "challenge": client_waiting["challenge"]
            }).encode(), addr)
            return

        instance[instance_id] = (addr, now, info["auth"])

        # 1. remove timeout
        for _k, _v in list(instance.items()):
            if now - _v[1] > 10:  # 10s超时
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
                s.sendto(json.dumps({
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
                s.sendto(json.dumps({
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
        if peer[2] != info["auth"]:
            logging.info("Client: %s auth check failed!",
                         str(self._clients_waiting[user]))
            del self._clients_waiting[user]
            s.sendto(json.dumps({
                "action": "peer-auth-failed"
            }).encode(), addr)
            return

        del self._clients_waiting[user]
        token = hmac.new(
            info["auth"].encode(), server_auth.encode(), digestmod='md5'
        ).hexdigest()[:16]
        content = json.dumps({
            "action": "peer-ready", "token": token
        }).encode()

        self._clients[user] = {"time": now, "instance": {}, "token": token}
        s.sendto(content, addr)
        s.sendto(content, peer[0])

    def __checkout_timeout(self, now):
        for k in list(self._clients.keys()):
            if now - self._clients[k]["time"] > self._client_record_timeout:
                logging.info(
                    "Drop out-of-date user:%s info:%s", k, str(self._clients[k]))
                del self._clients[k]

        for k in list(self._forward_table.keys()):
            if k not in self._forward_table:
                continue
            peer_addr = self._forward_table[k]
            if now - peer_addr[2] <= self._client_record_timeout:
                continue

            logging.info("Drop out-of-date forward:%s", k)
            del self._forward_table[k]
            peer_k = "%s:%d" % (peer_addr[0][0], peer_addr[0][1])
            if peer_k in self._forward_table:
                logging.info("Drop out-of-date forward:%s", peer_k)
                del self._forward_table[peer_k]

        for k in list(self._clients_waiting.keys()):
            if now - self._clients_waiting[k]["time"] > self._client_record_timeout:
                logging.info(
                    "Drop out-of-date user:%s waiting:%s", k, str(self._clients_waiting[k]))
                del self._clients_waiting[k]

    def run(self):
        la = self._sock.getsockname()
        last_timeout_check = time.time()
        logging.info("VPN Relay Server start on %s:%d", la[0], la[1])
        while True:
            r, _, _ = select.select([s], [], [], 10)
            now = time.time()

            if now > last_timeout_check + 10:
                self.__checkout_timeout(now)
                last_timeout_check = now

            if not r:
                continue

            data, addr = s.recvfrom(2048)

            # 1. just forward data
            k = "%s:%d" % (addr[0], addr[1])
            if k in self._forward_table:
                peer_addr = self._forward_table[k]

                if not peer_addr[1]:
                    logging.debug(
                        "Peer %s:%d not in forward table, drop msg:%s",
                        peer_addr[0][0], peer_addr[0][1], str(data))
                    continue

                s.sendto(data, peer_addr[0])
                peer_addr[2] = now
                continue

            # 2. do check
            try:
                info = json.loads(data.decode())
            except Exception as e:
                logging.error(
                    "Decode %s error(%s) addr:%s forward table: %s",
                    str(data), str(e), k, str(self._forward_table))
                continue

            ks = ["user", "action", "instance_id"]
            key_missing = False
            for _k in ks:
                if _k not in info:
                    logging.debug("Recv data: %s format invalid", str(info))
                    key_missing = True
                    break
            if key_missing:
                continue

            if info["action"] not in ["wait-peer", "peer-info", "request-forward"]:
                logging.debug("Unknow:%s method!", info["action"])
                continue

            action = info["action"]
            user = info["user"]
            instance_id = info["instance_id"]

            logging.debug("Recv client=%s:%d user=%s action=%s",
                          addr[0], addr[1], user, action)

            # 3. do user verify
            if action == "wait-peer":
                self.__do_auth(s, addr, info, now)
                continue

            # 4. exchange user info
            if user not in self._clients:
                continue

            client = self._clients[user]
            instance = client["instance"]

            if "token" not in info or client["token"] != info["token"]:
                #
                # 删除当前用户信息，需要用户重新协商
                #
                del self._clients[user]
                continue

            instance[instance_id] = (
                addr[0], addr[1], now, instance_id
            )

            # 1. remove timeout
            for ins_id, ins in list(instance.items()):
                if now - ins[2] > 2:  # record out of date
                    logging.info("Record: %s:%d out of date(%.2f)",
                                 ins[0], ins[1], now - ins[2])
                    del instance[ins_id]

            items = list(instance.items())
            if len(items) > 2:
                logging.error(
                    "More then 2 client using same accout!(%s)", str(items))
                del self._clients[user]
                continue

            if len(items) != 2:
                client["time"] = now
                continue

            peer = items[1][1] if items[0][0] == instance_id else items[0][1]
            # set forward table
            if info["action"] == "request-forward":
                assert k == "%s:%d" % (addr[0], addr[1])
                logging.info(
                    "add forward table: %s:%d => %s:%d",
                    addr[0], addr[1], peer[0], peer[1])
                peer_k = "%s:%d" % (peer[0], peer[1])

                if peer_k in self._forward_table:
                    assert self._forward_table[peer_k][0][0] == addr[0]

                    self._forward_table[peer_k] = [addr, True, now]
                    self._forward_table[k] = [(peer[0], peer[1]), True, now]
                    # NOTE: client记录已经无效，触发记录删除
                    client["time"] -= self._client_record_timeout
                else:
                    self._forward_table[k] = [(peer[0], peer[1]), False, now]

            # send peer info
            peer_info = {
                "addr": peer[0], "port": peer[1],
                "time": now,
                "addr-self": addr[0],
                "port-self": addr[1],
            }
            s.sendto(json.dumps(peer_info).encode(), addr)


if __name__ == '__main__':
    args = parse_args()
    set_loggint_format(args.verbose)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setblocking(False)
        s.bind(('0.0.0.0', args.port))
        VPNRelay(s, args.server_key).run()
