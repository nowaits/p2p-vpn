
import time
import string
import random


def random_str(l):
    return ''.join(random.sample(string.ascii_letters + string.digits, l))

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


class Rate(object):
    def __init__(self):
        self._time_last = time.time()
        self._cur_pkts = 0
        self._cur_bytes = 0
        self._total_pkts = 0
        self._total_bytes = 0
        self._pps = 0
        self._bps = 0

    def feed(self, len):
        now = time.time()

        self._total_pkts += 1
        self._total_bytes += len
        if now < self._time_last + 1:
            self._cur_pkts += 1
            self._cur_bytes += len
            return False
        else:
            if now >= self._time_last + 2:
                self._cur_pkts = 0
                self._cur_bytes = 0
            self._pps = self._cur_pkts
            self._bps = self._cur_bytes
            self._cur_pkts = 1
            self._cur_bytes = len
            self._time_last = now

            return True

    def status(self):
        now = time.time()
        if now > self._time_last + 1:
            self._pps = 0
            self._bps = 0

        return (self._pps, self._bps)

    def format_status(self):
        s = self.status()
        return (
            rate_format_str(s[0]),
            rate_format_str(s[1])
        )

    def format_total(self):
        return (
            rate_format_str(self._total_pkts),
            rate_format_str(self._total_bytes)
        )
