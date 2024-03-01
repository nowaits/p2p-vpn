
import time
import string
import random
import hashlib
import uuid
import socket


def random_str(l):
    return ''.join(random.sample(string.ascii_letters + string.digits, l))


def device_id():
    id = str(uuid.getnode())
    return hashlib.md5(id.encode()).hexdigest()[:16]


def alloc_local_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        while True:
            port = int(random.random()*65536)
            try:
                s.bind(("0.0.0.0", port))
                return port
            except OSError as e:
                continue

    return 0


def local_udp_port_binded(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.bind(("0.0.0.0", port))
            return False
        except OSError as e:
            return True

    return 0


def rate_format(rate):
    rate *= 1.0

    if rate < 1024:
        return (rate, "")
    elif rate < 1024 * 1024:
        return (rate / 1024, "K")
    elif rate < 1024 * 1024 * 1024:
        return (rate / 1024 / 1024, "M")
    elif rate < 1024 * 1024 * 1024 * 1024:
        return (rate / 1024 / 1024 / 1024, "G")
    elif rate < 1024 * 1024 * 1024 * 1024 * 1024:
        return (rate / 1024 / 1024 / 1024 / 1024, "T")
    else:
        return (rate / 1024 / 1024 / 1024 / 1024 / 1024, "P")


def rate_format_str(rate):
    r, t = rate_format(rate)

    if r == int(r):
        s = "%d" % r
    else:
        s = "%.2f" % r

    return s[:5] + t


def format_time_diff(diff):
    h = int(diff / 3600)
    m = int((diff - h * 3600)/60)
    s = int(diff - h * 3600 - m * 60)
    return "%03d:%02d:%02d" % (h, m, s)


def set_keep_alive(sock, after_idle=5, interval=10, max_fails=5):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, True)

    if hasattr(socket, "TCP_KEEPIDLE") and \
            hasattr(socket, "TCP_KEEPINTVL") and \
            hasattr(socket, "TCP_KEEPCNT"):
        sock.setsockopt(
            socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle)
        sock.setsockopt(
            socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval)
        sock.setsockopt(
            socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)
        return True
    elif hasattr(socket, "SIO_KEEPALIVE_VALS"):
        sock.ioctl(
            socket.SIO_KEEPALIVE_VALS,
            (1, after_idle * 1000, interval * 1000))
        return True
    else:
        return False


class Rate(object):
    def __init__(self):
        self._time_last = 0
        self._time_start = 0
        self._time_now = 0
        self._cur_pkts = 0
        self._cur_bytes = 0
        self._total_pkts = 0
        self._total_bytes = 0
        self._pps = 0
        self._bps = 0

    def feed(self, now, len, num=1):
        if self._time_last == 0:
            self._time_last = now
            self._time_start = now

        self._time_now = now
        if now < self._time_last + 1:
            self._cur_pkts += num
            self._cur_bytes += len
            return False
        else:
            if now >= self._time_last + 2:
                self._cur_pkts = 0
                self._cur_bytes = 0
            self._pps = self._cur_pkts
            self._bps = self._cur_bytes
            self._total_pkts += self._cur_pkts
            self._total_bytes += self._cur_bytes
            self._cur_pkts = num
            self._cur_bytes = len
            self._time_last = now

            return True

    def now(self):
        now = time.time()
        if now > self._time_last + 1:
            self._pps = 0
            self._bps = 0

        return (self._pps, self._bps)

    def avg(self):
        time_diff = self._time_now - self._time_start

        if time_diff == 0:
            return (0, 0)

        return (self._total_pkts/time_diff, self._total_bytes/time_diff)

    def total(self):
        return (self._total_pkts, self._total_bytes)

    def format_now(self):
        s = self.now()
        return (
            rate_format_str(s[0]),
            rate_format_str(s[1])
        )

    def format_avg(self):
        s = self.avg()
        return (
            rate_format_str(s[0]),
            rate_format_str(s[1])
        )

    def format_total(self):
        s = self.total()
        return (
            rate_format_str(s[0]),
            rate_format_str(s[1])
        )
