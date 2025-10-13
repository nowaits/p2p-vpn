
import time
import string
import random
import hashlib
import uuid
import socket
import platform
import subprocess
import re
import ipaddress
import select


def random_str(l):
    return ''.join(random.sample(string.ascii_letters + string.digits, l))


def device_id():
    id = str(uuid.getnode())
    return hashlib.md5(id.encode()).hexdigest()[:16]


def alloc_local_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("0.0.0.0", 0))
        return s.getsockname()[1]


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
    d = int(diff / (3600 * 24))
    h = int(diff % (3600 * 24) / 3600)
    m = int(diff % 3600 / 60)
    s = int(diff % 60)

    if d == 0:
        return "%02d:%02d:%02d" % (h, m, s)

    return "%d.%02d:%02d:%02d" % (d, h, m, s)


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


def get_all_ipv4(include_loopback=False):
    """返回系统所有 IPv4 地址及前缀长度，例如：
       [("192.168.1.10", 24), ("10.0.0.5", 8)]
    """
    results = []
    system = platform.system().lower()

    if system == "windows":
        out = subprocess.run(["ipconfig"], capture_output=True,
                             text=True, errors="ignore").stdout
        pairs = re.findall(
            r"IPv4[^\:]*:\s*([\d\.]+).*?(?:子网掩码|Subnet Mask)[^\:]*:\s*([\d\.]+)",
            out, re.IGNORECASE | re.DOTALL
        )
        for ip, mask in pairs:
            if not include_loopback and ip.startswith("127."):
                continue
            plen = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
            results.append((ip, plen))

    else:
        try:
            out = subprocess.run(["ip", "-4", "-o", "addr", "show"],
                                 capture_output=True, text=True, errors="ignore").stdout
            for ip, plen in re.findall(r"inet\s+([\d\.]+)/(\d+)", out):
                if not include_loopback and ip.startswith("127."):
                    continue
                results.append((ip, int(plen)))
        except FileNotFoundError:
            out = subprocess.run(
                ["ifconfig"], capture_output=True, text=True, errors="ignore").stdout
            for ip, mask in re.findall(r"inet\s+(?:addr:)?([\d\.]+).*?(?:Mask:|netmask\s+)([\d\.x]+)", out, re.IGNORECASE):
                if not include_loopback and ip.startswith("127.") or not mask:
                    continue
                if "0x" in mask:
                    mask = str(ipaddress.IPv4Address(int(mask, 16)))
                plen = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
                results.append((ip, plen))

    return results


def check_ip_with_plen_equal(ip0, ip1, plen):
    net0 = ipaddress.IPv4Network(f"{ip0}/{plen}", strict=False)
    net1 = ipaddress.IPv4Network(f"{ip1}/{plen}", strict=False)
    return net0.network_address == net1.network_address


def probe_ip_in_lan(local_port, remote_port, local_is_server):
    '''
    使用UDP广播探测两个主机是否在一个局域网，并返回互通的IP对
    '''
    local_ips = get_all_ipv4()
    ss = {}

    if local_is_server:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", local_port))
        s.setblocking(False)
        ss[s.fileno()] = s
    else:
        for ip, _ in local_ips:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.bind((ip, local_port))
            s.setblocking(False)
            ss[s.fileno()] = s

    ws = ss.values()
    addr_pair = {}
    start_time = time.time()

    msg = "tunnel-building".encode()
    resp_time = 0
    while time.time() < start_time + 5 and resp_time < 3:
        r, w, _ = select.select(ss.values(), ws, [], 0.5)
        ws = []

        for s in r:
            data, addr = s.recvfrom(1024)

            if data != msg:
                continue

            resp_time += 1
            if addr[0] not in addr_pair:
                for ip, plen in local_ips:
                    if check_ip_with_plen_equal(ip, addr[0], plen):
                        addr_pair[addr[0]] = ip

            if local_is_server:
                s.sendto(msg, addr)

        if not local_is_server:
            for s in w:
                try:
                    s.sendto(msg, ('255.255.255.255', remote_port))
                except:
                    del ss[s.fileno()]
                    s.close()

        if not r and not w:
            ws = ss.values()

    for s in ss.values():
        s.close()

    if addr_pair:
        k = sorted(addr_pair)[0]  # 返回排序最小的一个
        return addr_pair[k], k
    else:
        return None, None


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
