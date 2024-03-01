import os
import sys
import socket
import select
import time
import logging
import argparse
import json
import hashlib

assert sys.version_info >= (3, 6)

SCRIPT = os.path.abspath(__file__)
PWD = os.path.dirname(SCRIPT)

LOG_LEVELS = (
    logging.NOTSET, logging.DEBUG,
    logging.INFO, logging.WARNING,
    logging.ERROR, logging.CRITICAL)
LOG_CHOICES = list(map(lambda x: logging.getLevelName(x), LOG_LEVELS))

parser = argparse.ArgumentParser(description="server")
parser.add_argument(
    "--port", "-p", type=int,
    default=5100, help="server port, default 5100")
parser.add_argument(
    '--verbose', "-v", default=LOG_CHOICES[2], choices=LOG_CHOICES, help="log level")
parser.add_argument(
    "--logfile", type=str, default=None,
    help="if set, then running log redirect to file")
args = parser.parse_args()

debug_info = " %(filename)s:%(lineno)d %(funcName)s"

if args.logfile:
    log_file = os.path.join(PWD, args.logfile)
    log_file_fd = open(log_file, 'a')
else:
    log_file_fd = sys.stdout
logging.basicConfig(
    level=args.verbose,
    stream=log_file_fd,
    format='[%(asctime)s %(levelname)s' + debug_info + ']: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

address = ('0.0.0.0', args.port)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setblocking(False)
s.bind(address)

logging.info("Service start on %s:%d", address[0], address[1])

clients = {}
forward_table = {}
clients_waiting = {}


def gen_challenge():
    s = str(time.time()).encode()
    return hashlib.md5(s).hexdigest()[:16]


while True:
    r, _, _ = select.select([s], [], [], 10)

    if not r:
        if clients:
            logging.info(
                "Drop out-of-date info:%s", str(clients))
        if forward_table:
            logging.info(
                "Drop out-of-date forward table:%s",
                str(forward_table))
        if clients_waiting:
            logging.info(
                "Drop out-of-date waiting table:%s",
                str(clients_waiting))
        clients = {}
        forward_table = {}
        clients_waiting = {}
        continue

    now = time.time()
    data, addr = s.recvfrom(2048)

    # 1. just forward data
    k = "%s:%d" % (addr[0], addr[1])
    if k in forward_table:
        peer_addr = forward_table[k]

        if not peer_addr[1]:
            logging.debug(
                "Peer %s:%d not in forward table, drop msg:%s",
                peer_addr[0][0], peer_addr[0][1], str(data))
            continue

        s.sendto(data, peer_addr[0])
        continue

    # 2. do check
    try:
        info = json.loads(data.decode())
    except Exception as e:
        logging.error(
            "Decode %s error(%s) addr:%s forward table: %s",
            str(data), str(e), k, str(forward_table))
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

    logging.debug("Recv client: %s:%d action: %s", addr[0], addr[1], action)

    # 3. do user verify
    if action == "wait-peer":
        if user not in clients_waiting:
            clients_waiting[user] = {"instance": {}}
        client_waiting = clients_waiting[user]
        instance = client_waiting["instance"]

        # 每隔1分钟自动更新challenge
        challenge_update = False
        if "challenge" not in client_waiting or \
                now - client_waiting["time"] > 60:
            client_waiting["challenge"] = gen_challenge()
            client_waiting["time"] = now
            challenge_update = True

        if challenge_update or "auth" not in info:
            s.sendto(json.dumps({
                "action": "challenge",
                "challenge": client_waiting["challenge"]
            }).encode(), addr)
            continue

        instance[instance_id] = (addr, now, info["auth"])

        # 1. remove timeout
        for _k, _v in list(instance.items()):
            if now - _v[1] > 10:  # 10s超时
                del instance[_k]

        items = list(instance.items())
        if len(items) > 2:
            logging.error(
                "More then 2 client using same accout!(%s)", str(items))
            del instance[user]
            continue

        if len(items) != 2:
            continue

        peer = items[1][1] if items[0][0] == instance_id else items[0][1]
        if peer[2] != info["auth"]:
            logging.info("Client: %s auth check failed!",
                         str(clients_waiting[user]))
            del clients_waiting[user]
            s.sendto(json.dumps({
                "auth-failed": "failed"
            }).encode(), addr)
            continue

        del clients_waiting[user]
        token = gen_challenge()
        content = json.dumps({
            "action": "peer-ready",
            "token": token
        }).encode()

        clients[user] = {"time": now, "instance": {}, "token": token}
        s.sendto(content, addr)
        s.sendto(content, peer[0])
        continue

    # 4. exchange user info
    if user not in clients:
        continue

    client = clients[user]
    instance = client["instance"]

    if "token" not in info or client["token"] != info["token"]:
        #
        # 删除当前用户信息，需要用户重新协商
        #
        del clients[user]
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
        logging.error("More then 2 client using same accout!(%s)", str(items))
        del clients[user]
        continue

    if len(items) != 2:
        continue

    peer = items[1][1] if items[0][0] == instance_id else items[0][1]
    # set forward table
    if info["action"] == "request-forward":
        assert k == "%s:%d" % (addr[0], addr[1])
        logging.info(
            "add forward table: %s:%d => %s:%d",
            addr[0], addr[1], peer[0], peer[1])
        peer_k = "%s:%d" % (peer[0], peer[1])

        if peer_k in forward_table:
            assert forward_table[peer_k][0][0] == addr[0]
            assert forward_table[peer_k][0][1] == addr[1]

            forward_table[peer_k] = (addr, True)
            forward_table[k] = ((peer[0], peer[1]), True)
        else:
            forward_table[k] = ((peer[0], peer[1]), False)

    # send peer info
    peer_info = {
        "addr": peer[0], "port": peer[1],
        "time": time.time()
    }
    s.sendto(json.dumps(peer_info).encode(), addr)

s.close()
