
import time


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
    rate *= 1.0

    if rate < 1024:
        s = "%d" % rate
        t = ""
    elif rate < 1024 * 1024:
        s = "%.2f" % (rate / 1024)
        t = "K"
    elif rate < 1024 * 1024 * 1024:
        s = "%.2f" % (rate / 1024 / 1024)
        t = "M"
    elif rate < 1024 * 1024 * 1024 * 1024:
        s = "%.2f" % (rate / 1024 / 1024 / 1024)
        t = "G"
    elif rate < 1024 * 1024 * 1024 * 1024 * 1024:
        s = "%.2f" % (rate / 1024 / 1024 / 1024 / 1024)
        t = "T"
    else:
        s = "%.2f" % (rate / 1024 / 1024 / 1024 / 1024 / 1024)
        t = "P"

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
            self._pps = self._cur_pkts / (now - self._time_last)
            self._bps = self._cur_bytes / (now - self._time_last)
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
