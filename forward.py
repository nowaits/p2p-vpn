import sys
import socket
import select
import threading
import logging
from collections import deque
import argparse


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
    parser = argparse.ArgumentParser(description="port forward")

    parser.add_argument("--rip", type=str, required=True, help="remote ip")
    parser.add_argument("--rport", type=int, required=True, help="remote port")
    parser.add_argument("--lport", type=int, required=True, help="local port")
    parser.add_argument(
        '--verbose', default=LOG_CHOICES[2],
        choices=LOG_CHOICES, help="log level default:%s" % (LOG_CHOICES[2]))

    return parser.parse_args()


class PortForward(object):
    def __init__(self, is_tcp, local_addr, remote_addr):
        self._sock_type = socket.SOCK_STREAM if is_tcp else socket.SOCK_DGRAM
        self._sock_local = socket.socket(socket.AF_INET, self._sock_type)
        self._sock_local.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock_local.bind(local_addr)
        self._sock_local.listen(10)
        self._local_addr = local_addr
        self._remote_addr = remote_addr
        self._threads = []
        self._terminate = False

    def __enter__(self):
        logging.info(
            "forward service start(%s:%d=>%s:%d)!",
            self._local_addr[0], self._local_addr[1],
            self._remote_addr[0], self._remote_addr[1])
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        assert self._terminate
        self._sock_local.close()
        for t in self._threads:
            t.join()
        logging.info("PortForward closed!")
        pass

    def run(self):
        while not self._terminate:
            try:
                (sock1, client_addr) = self._sock_local.accept()
            except (KeyboardInterrupt, Exception):
                self._terminate = True
                logging.debug('Stop port forward service.')
                break

            sock2 = socket.socket(socket.AF_INET, self._sock_type)
            t = threading.Thread(
                target=self.forward_request,
                args=(sock1, sock2))
            t.daemon = True
            t.start()
            self._threads.append(t)

    def forward_request(self, sock1, sock2):
        t = threading.current_thread()
        try:
            sock2.connect(self._remote_addr)
        except Exception:
            sock2.close()
            logging.error('Unable to connect to the remote server.')
            self._threads.remove(t)
            return

        try:
            self.forward_socket(sock1, sock2)
        except BrokenPipeError:
            pass
        except Exception as e:
            logging.error('Exit %s', str(e))
            pass

        self._threads.remove(t)

    def forward_socket(self, soc1, soc2):

        soc1.setblocking(False)
        soc2.setblocking(False)
        q1 = deque()
        q2 = deque()

        rs = [soc1, soc2]
        ws = []
        while not self._terminate and rs:
            r, w, _ = select.select(rs, ws, [], 1)

            ws = []

            if soc1 in r:
                data = soc1.recv(2048)
                q1.append(data)
            if soc2 in r:
                data = soc2.recv(2048)
                q2.append(data)

            if soc1 in w and q2:
                soc1.send(q2.popleft())
            if soc2 in w and q1:
                soc2.send(q1.popleft())

            if q1:
                ws.append(soc2)
            if q2:
                ws.append(soc1)

        logging.info("forward thread exit!")


if __name__ == '__main__':
    args = parse_args()
    set_loggint_format(args.verbose)
    local_addr = ("0.0.0.0", args.lport)
    remote_addr = (args.rip, args.rport)

    with PortForward(1, local_addr, remote_addr) as f:
        f.run()

    logging.info('port forward exit')
