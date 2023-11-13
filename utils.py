
import time
import string
import random
import hashlib
import uuid


def random_str(l):
    return ''.join(random.sample(string.ascii_letters + string.digits, l))


def device_id():
    id = str(uuid.getnode())
    return hashlib.md5(id.encode()).hexdigest()[:16]


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

    def feed(self, now, len):
        if self._time_last == 0:
            self._time_last = now
            self._time_start = now

        self._time_now = now
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

    def format_avg(self):
        time_diff = self._time_now - self._time_start

        if time_diff == 0:
            return ("", "")

        return (
            rate_format_str(self._total_pkts/time_diff),
            rate_format_str(self._total_bytes/time_diff)
        )

    def format_total(self):
        return (
            rate_format_str(self._total_pkts),
            rate_format_str(self._total_bytes)
        )
