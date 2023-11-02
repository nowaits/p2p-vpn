import socket
import select
import time
import logging
import sys
import argparse
import json

LOG_LEVELS = (
    logging.NOTSET, logging.DEBUG,
    logging.INFO, logging.WARNING,
    logging.ERROR, logging.CRITICAL)
LOG_CHOICES = list(map(lambda x: logging.getLevelName(x), LOG_LEVELS))

parser = argparse.ArgumentParser(description="server")
parser.add_argument("--port", "-p", type=int,
                    default=5100, help="server port, default 5100")
parser.add_argument(
    '--verbose', "-v", default=LOG_CHOICES[2], choices=LOG_CHOICES, help="log level")
args = parser.parse_args()

debug_info = " %(filename)s %(funcName)s:%(lineno)d "
logging.basicConfig(
    level=args.verbose,
    stream=sys.stdout,
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

while True:
    r, _, _ = select.select([s], [], [], 10)

    if not r:
        if clients:
            logging.info("Drop out-of-date info:%s", str(clients))
        if forward_table:
            logging.info("Drop out-of-date forward table:%s",
                         str(forward_table))
        clients = {}
        forward_table = {}
        continue

    data, addr = s.recvfrom(2048)

    # 1. just forward data
    k = str(addr)
    if k in forward_table:
        peer_addr = forward_table[k]
        s.sendto(data, peer_addr)
        continue

    # 2. other
    try:
        info = json.loads(data.decode())
    except Exception as e:
        logging.error("Decode %s error(%s) addr:%s  %s",
                      str(data), str(e), k, str(forward_table))
        continue

    if "user" not in info or "action" not in info:
        logging.debug("Recv data: %s format invalid", str(info))
        continue

    if info["action"] not in ["peer-info", "request-forward"]:
        logging.debug("Unknow:%s method!", info["action"])
        continue

    user = info["user"]
    if user not in clients:
        clients[user] = {}

    client = clients[user]

    now = time.time()
    logging.info("Recv client: %s:%d", addr[0], addr[1])
    client[k] = (addr[0], addr[1], now)

    peer_info = None
    for _k, _v in client.items():
        if _k == k:
            continue
        if now - _v[2] > 2:  # record out of date
            logging.debug("Record: %s:%d out of date(%.2f)",
                          _v[0], _v[1], now - _v[2])
            del client[_k]
            continue

        if info["action"] == "request-forward":
            logging.info(
                "set forward table: %s:%d => %s:%d",
                addr[0], addr[1], _v[0], _v[1])
            forward_table[k] = (_v[0], _v[1])
        peer_info = {"addr": _v[0], "port": _v[1]}

    if peer_info:
        s.sendto(json.dumps(peer_info).encode(), addr)

s.close()
