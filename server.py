import socket
import select
import time
import logging
import sys
import argparse

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

while True:
    r, _, _ = select.select([s], [], [], 10)

    if not r:
        if clients:
            logging.info("Drop out-of-date info:%s", str(clients))
        clients = {}
        continue

    data, addr = s.recvfrom(2048)
    try:
        info = data.decode().split(":")
    except Exception as e:
        logging.error("Decode %s error(%s)", str(data), str(e))
        continue

    if len(info) != 2 or info[0] != "token":
        logging.debug("Recv data: %s format invalid", str(info))
        continue

    token = info[1]
    if not clients.has_key(token):
        clients[token] = {}

    client = clients[token]
    now = time.time()

    logging.info("Recv client: %s:%d token:%s", addr[0], addr[1], token)
    client[addr[0]] = (addr[1], now)

    peer = None
    for k, v in client.items():
        if k == addr[0]:
            continue
        if now - v[1] > 2:  # record out of date
            logging.debug("Record: %s:%d out of date(%.2f)",
                          k, v[0], now - v[1])
            del client[k]
            continue

        peer = "%s:%d" % (k, v[0])

    if not peer:
        continue

    s.sendto(peer.encode(), addr)

s.close()
