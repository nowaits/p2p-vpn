import os
import sys
import socket
import logging
import argparse

SCRIPT = os.path.abspath(__file__)
PWD = os.path.dirname(SCRIPT)
sys.path.insert(0, PWD + "/..")

from vpn_server import VPNServer  # noqa: E402

assert sys.version_info >= (3, 6)

LOG_LEVELS = (
    logging.NOTSET, logging.DEBUG,
    logging.INFO, logging.WARNING,
    logging.ERROR, logging.CRITICAL)
LOG_CHOICES = list(map(lambda x: logging.getLevelName(x), LOG_LEVELS))


def set_loggint_format(conf):
    debug_info = " %(filename)s:%(lineno)d %(funcName)s"

    if conf.logfile:
        log_file = os.path.join(PWD, conf.logfile)
        log_file_fd = open(log_file, 'w')
    else:
        log_file_fd = sys.stdout

    logging.basicConfig(
        level=conf.verbose,
        stream=log_file_fd,
        format='[%(asctime)s %(levelname)s' + debug_info + ']: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def parse_args():
    parser = argparse.ArgumentParser(description="server")
    parser.add_argument(
        "--port", "-p", type=int,
        default=5200, help="server port, default 5200")
    parser.add_argument(
        "--server-key", type=str, default=None, help="server authentication key")
    parser.add_argument(
        '--verbose', "-v", default=LOG_CHOICES[2], choices=LOG_CHOICES, help="log level")
    parser.add_argument(
        "--logfile", type=str, default=None,
        help="if set, then running log redirect to file")
    return parser.parse_args()


if __name__ == '__main__':
    conf = parse_args()
    set_loggint_format(conf)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s0, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s1:
        s0.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        s0.bind(('0.0.0.0', conf.port))
        s1.bind(('0.0.0.0', conf.port))
        s0.listen(5)

        s0.setblocking(False)
        s1.setblocking(False)
        VPNServer(s0, s1, conf.server_key).run()

    logging.info("VPN server exit")
