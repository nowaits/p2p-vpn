import os

import sys
import socket
import select
import time
import argparse
import logging
import json
import traceback
import hmac

SCRIPT = os.path.abspath(__file__)
PWD = os.path.dirname(SCRIPT)
sys.path.insert(0, PWD + "/..")

import libs  # noqa: E402
from worker import VPN  # noqa: E402
from tunnel_builder_udp import nat_tunnel_build_udp  # noqa: E402
from tunnel_builder_tcp import nat_tunnel_build_tcp  # noqa: E402

assert sys.version_info >= (3, 6)

SCRIPT = os.path.abspath(__file__)
PWD = os.path.dirname(SCRIPT)

LOG_LEVELS = (
    logging.NOTSET, logging.DEBUG,
    logging.INFO, logging.WARNING,
    logging.ERROR, logging.CRITICAL)
LOG_CHOICES = list(map(lambda x: logging.getLevelName(x), LOG_LEVELS))


class VPNTunnelManager:
    #
    #
    # 隧道在：p2p tcp, p2p udp, forward tcp, forward udp四种类型之间的切换逻辑
    #
    #   A) 隧道协商成功时，隧道类型为：
    #       a) p2p类型:
    #           1. p2p协商成功事件+1
    #           2. 记录成功事件R，并保存24小时内所有的R
    #           3. 隧道正常工作时，会通过心跳计算路径时延，并保存到对应的R中
    #           4. 当时延大于delay_max且隧道运行时间大于5min时，隧道会自动断开，进入重新协商逻辑
    #       b) forward类型:
    #           1. 重置p2p隧道事件（删除所有p2p记录的R）
    #           2. 如果生命周期内p2p隧道协商成功过，且forward隧道维持大于1h，
    #               则自动断开隧道，进入重新协商逻辑
    #
    #   B) 两端等待协商阶段
    #       1. 分别向服务器上传自己监听地址及所有出口IP，当双向准备协商时，会收到对方相关信息
    #       2. 如果两端公网地址一样，可能互通或单方直通，此时进入：
    #           双向分别向对方出口IP及监听端口发起同步，收到正常回复，则UDP p2p隧道创建成功
    #       3. 2未成功创建，则进入隧道协商逻辑
    #
    #   C) 隧道协商逻辑
    #       1. 计算24小时内，p2p tcp/udp类型隧道成功创建的次数: tcp-time/udp-time
    #       2. 计算最近一次p2p tcp/udp类型隧道工作时的平均时延: tcp-delay/udp-delay
    #       3. 优先尝试tcp-time/udp-time最小的类型：每种类型对应的
    #           delay > delay_max时，跳过协商
    #       4. 以上三步完成之后，如果隧道还未协商成功，则依次尝试forward tcp/forward udp
    #           直到成功为止
    #
    #   D) 其它
    #       1. 如果网络不能打洞，则隧道最终维持在tcp/udp forward类型
    #       2. 如果网络允许打洞，但p2p隧道时延太大，则在forward隧道之后，会尝试p2p隧道
    #
    def __init__(self):
        self.delay = 0
        self.delay_max = 100e3  # 100ms
        self.is_tcp = True
        self.start_time = True
        self.connect_time = 0
        self._is_p2p = True
        self._p2p_ok_time = 0

        self._p2p_last_24h_connect = [[], []]

    @property
    def is_p2p(self):
        return self._is_p2p

    @is_p2p.setter
    def is_p2p(self, value):
        #
        #   设置之前，保证self.is_tcp方法已经被正确设置
        #
        self._is_p2p = value
        if self._is_p2p:
            self._p2p_ok_time += 1
            record = {"time": time.time(), "delay": []}

            self._p2p_last_24h_connect[self.is_tcp].append(record)
            #
            # 删除超过24小时的记录
            #

            def filter_last_24h(rs):
                if not rs:
                    return []
                last_record = rs[-1]
                return [r for r in rs if last_record["time"] - r["time"] < 3600 * 24]

            self._p2p_last_24h_connect[0] = filter_last_24h(
                self._p2p_last_24h_connect[0])
            self._p2p_last_24h_connect[1] = filter_last_24h(
                self._p2p_last_24h_connect[1])
        else:
            self._p2p_last_24h_connect = [[], []]

        self.connect_time += 1
        self.start_time = time.time()

    def update_delay(self, delay):
        #
        # @desc: 时延测量逻辑
        #
        #   vpn隧道无数据或每隔5分钟时会发送一次心跳报文，格式：
        #       req: <local intance id:seq no:time>
        #       resp: <local instance id: peer seq no:peer time>
        #   resp接收者计算时延：
        #       delay = (time.time() - <peer time>)/2
        #
        # @return: 返回是否应该重新协商VPN隧道
        #
        #   1. p2p => forward
        #       delay大于delay_max、当前为p2p、且已经运行5分钟，自动切换到转发
        #   2. forward => p2p
        #       当前是forward且成功切换过p2p，每隔1个小时，尝试一次p2p
        #
        self.delay = int(delay + (self.delay - delay)/16)
        if self.is_p2p:
            rs = self._p2p_last_24h_connect[self.is_tcp]
            assert len(rs) > 0

            rs[-1]["delay"].append(self.delay)
            #
            # 取最新5个的平均值(防止丢包导致时延过大)
            #
            latest_delays = rs[-1]["delay"][-5:]
            delay_avg = sum(latest_delays)/len(latest_delays)
            msg = f"P2P VPN exit (delay {latest_delays} >= {self.delay_max} large)"
            return self.is_p2p and delay_avg > self.delay_max \
                and time.time() - self.start_time >= 300, msg
        else:
            msg = f"Forward VPN exit (try p2p)"
            return self._p2p_ok_time > 0 and time.time() - self.start_time >= 3600, msg

    def __get_last_connect_avg_delay(self, is_tcp):
        rs = self._p2p_last_24h_connect[is_tcp]
        if len(rs) == 0:
            return 0

        last_record = rs[-1]
        if len(last_record["delay"]) == 0:
            return 0

        return sum(last_record["delay"])/len(last_record["delay"])

    def p2p_preferd_method(self):
        tcp_reconnect_times = len(self._p2p_last_24h_connect[True])
        udp_reconnect_times = len(self._p2p_last_24h_connect[False])

        delay_tcp = self.__get_last_connect_avg_delay(True)
        delay_udp = self.__get_last_connect_avg_delay(False)

        m = "tcp"
        if tcp_reconnect_times > udp_reconnect_times:
            m = "udp"

        return m, delay_tcp, delay_udp


vpn_tunnel_mgr = VPNTunnelManager()


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


def parse_args(argv=None):
    def str2bool(str):
        return True if str.lower() == 'true' else False

    parser = argparse.ArgumentParser(description="vpn")

    parser.add_argument(
        "--client", "-c", action='store_true', help="client mode")
    parser.add_argument(
        "--using-udp", action='store_true', help="using udp proto")
    parser.add_argument(
        "--show-status", default="true", type=str2bool, help="show status")
    parser.add_argument(
        "--cs-vpn", action='store_true', help="set for local vpn")
    parser.add_argument(
        "--server", "-s", type=str, required=True, help="server IP")
    parser.add_argument(
        "--server-key", type=str, default=None, help="server authentication key")
    parser.add_argument(
        "--port", "-p", type=int, default=5200,
        help="server port, default 5200")
    parser.add_argument(
        #
        # 当前测试手机热点最大MTU为1341
        #
        "--mtu", type=int, default=1341,
        help="mtu, default 1341")
    parser.add_argument(
        "--timeout", type=int, default=30,
        help="connect timeout, default 30s")
    parser.add_argument(
        "--port-try-range", "-r", type=int, default=100,
        help="port try range, default 100")
    parser.add_argument(
        "--vip", type=str, default="10.0.0.1",
        help="virtual ip, default 10.0.0.1")
    parser.add_argument(
        "--vmask", type=str, default="255.255.255.0",
        help="virtual ip mask, default 255.255.255.0")
    parser.add_argument("--user", type=str, help="user account")
    parser.add_argument("--passwd", type=str, help="user passwd")
    parser.add_argument(
        "--run-as-service", action='store_true', help="run as vpn service")
    parser.add_argument(
        "--p2p-test", action='store_true', help="test p2p throughout")
    parser.add_argument("--logfile", type=str, default=None,
                        help="if set, then running log redirect to file")
    parser.add_argument(
        '--verbose', default=LOG_CHOICES[2],
        choices=LOG_CHOICES, help="log level default:%s" % (LOG_CHOICES[2]))

    return parser.parse_args(argv)


class AuthCheckFailed(Exception):
    pass


def waiting_nat_peer_online(conf, s):
    s.setblocking(False)
    s.bind(("0.0.0.0", 0))
    ws = [s]

    challenge = None
    local_ips = libs.get_all_ipv4()
    while True:
        r, w, _ = select.select([s], ws, [], 10)
        ws = []
        if s in r:
            data, addr = s.recvfrom(2048)
            try:
                if addr[0] != conf.server_ip or addr[1] != conf.port:
                    continue

                info = json.loads(data.decode())
                if type(info) != dict:
                    logging.error(
                        "Resp:%s from server invalid!", str(info))
                    continue
            except Exception as e:
                logging.error("Decode %s error(%s)", str(data), str(e))
                continue

            if "action" in info:
                action = info["action"]
                if action == "challenge":
                    if "challenge" not in info:
                        continue

                    if challenge != info["challenge"]:
                        ws.append(s)
                        challenge = info["challenge"]
                elif action == "server-auth-required":
                    raise AuthCheckFailed("server auth required!")
                elif action == "server-auth-failed":
                    raise AuthCheckFailed("server auth failed!")
                elif action == "peer-auth-failed":
                    raise AuthCheckFailed("peer auth failed!")
                elif action == "peer-ready":
                    for k in ["token", "public-addr", "peer-addr", "peer-local", "peer-ip4"]:
                        if k not in info:
                            raise Exception(
                                "response format error!(%s)", str(info))
                    return info["token"], info["public-addr"], \
                        info["peer-addr"], info["peer-local"], info["peer-ip4"]
                else:
                    logging.error("Unknow action:%s", action)
                    continue

        if s in w:
            content = {
                "user": conf.user,
                "instance_id": conf.instance_id,
                "action": "wait-peer",
                "local-addr": s.getsockname(),
                "local-ipv4": local_ips,
            }

            if challenge:
                content["auth"] = hmac.new(
                    challenge.encode(),
                    (conf.user+conf.passwd).encode(),
                    digestmod='md5'
                ).hexdigest()[:16]
                if conf.server_key:
                    content["server-auth"] = hmac.new(
                        challenge.encode(),
                        conf.server_key.encode(),
                        digestmod='md5'
                    ).hexdigest()[:16]
            s.sendto(json.dumps(content).encode(),
                     (conf.server_ip, conf.port))

        if not r and not w:
            ws.append(s)


def setup_cs_vpn(conf):
    proto = socket.SOCK_STREAM if not conf.using_udp else socket.SOCK_DGRAM
    proto_str = "tcp" if not conf.using_udp else "udp"
    s = socket.socket(socket.AF_INET, proto)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    peer = None

    if conf.client:
        peer = (conf.server, conf.port)
        s.connect((conf.server, conf.port))
    else:
        s.bind(("0.0.0.0", conf.port))
        if not conf.using_udp:
            s.listen(1)
            # wait client
            ls = s
            s, peer = s.accept()
            ls.close()

    s.setblocking(False)
    # negotiate
    recv_left = b''
    connect_finish = False
    synced = False
    while not connect_finish:
        r, w, _ = select.select([s], [s], [], 1)
        if not conf.client:
            if s in w and synced:
                p = libs.packet_pack(
                    'ACK'.encode(), libs.PacketHeader.control)
                s.send(p)
                connect_finish = True

            if s in r:
                if not conf.using_udp:
                    d = s.recv(2048)
                else:
                    d, peer = s.recvfrom(2048)

                ok, ps, recv_left = \
                    libs.packet_unpack_all(recv_left + d)
                if not ok:
                    raise Exception("VPN Packet stream error!")

                for t, p in ps:
                    if t == libs.PacketHeader.control and p.decode() == "SYNC":
                        if conf.using_udp:
                            s.connect(peer)
                        synced = True
            else:
                time.sleep(0.5)
        else:
            if s in w:
                d = libs.packet_pack(
                    'SYNC'.encode(), libs.PacketHeader.control)
                s.send(d)

            if s in r:
                if not conf.using_udp:
                    d = s.recv(2048)
                else:
                    d, peer = s.recvfrom(2048)

                ok, ps, recv_left = \
                    libs.packet_unpack_all(recv_left + d)
                if not ok:
                    raise Exception("VPN Packet stream error!")

                for t, p in ps:
                    if t == libs.PacketHeader.control and p.decode() == 'ACK':
                        connect_finish = True
            else:
                time.sleep(0.5)

    if not conf.client:
        logging.info(f"connect server: {proto_str}://{peer[0]}:{peer[1]} ok")
    else:
        logging.info(f"client connect: {proto_str}://{peer[0]}:{peer[1]} ok")
    tun = (conf.vip, conf.vmask, conf.mtu)
    with VPN(conf.instance_id, tun, s, vpn_tunnel_mgr, conf.show_status, conf.tun_handle) as v:
        v.run()


def test_throughput(s, duration):
    time_last = time.time()
    seconds = 0
    data = 1400*'X'
    rx_rate = libs.Rate()
    tx_rate = libs.Rate()
    recv_left = b''
    while seconds < duration:
        r, w, _ = select.select([s], [s], [], 1)
        now = time.time()
        if s in r:
            d = s.recv(2048)

            ok, ps, recv_left = \
                libs.packet_unpack_all(recv_left + d)
            if not ok:
                raise Exception("VPN Packet stream error!")

            for _, p in ps:
                rx_rate.feed(now, len(p.decode()))
        if s in w:
            d = libs.packet_pack(data.encode(), libs.PacketHeader.data)
            l = s.send(d)
            tx_rate.feed(now, l)

        if time_last + 1 < time.time():
            time_last = now
            r0 = rx_rate.format_now()
            r1 = tx_rate.format_now()
            a0 = rx_rate.format_avg()
            a1 = tx_rate.format_avg()
            t0 = rx_rate.format_total()
            t1 = tx_rate.format_total()
            logging.info(
                "Rate(%s) "
                "RX-TX: %s/%s-%s/%s TOTAL: %s/%s" % (
                    libs.format_time_diff(seconds),
                    r0[1], a0[1],
                    r1[1], a1[1],
                    t0[1], t1[1]))
            seconds += 1
    s.close()


def setup_p2p_vpn(conf):
    if not conf.user or not conf.passwd:
        logging.error("Missing user or passwd for p2p vpn!")
        sys.exit()

    # do waiting peer online
    logging.info("Instance %s Waiting peer online...", conf.instance_id)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    token, public_addr, peer_addr, peer_local, peer_ipv4 = \
        waiting_nat_peer_online(conf, s)

    local_vpn_ok = False
    if public_addr[0] == peer_addr[0]:
        logging.info(
            f"Checking peer={public_addr[0]}:{public_addr[1]} in same LAN...")
        ws = [s]
        last_time = time.time()
        resp_addr = None
        local_addr = s.getsockname()
        while not local_vpn_ok:
            r, w, _ = select.select([s], ws, [], 0.5)
            ws = []

            now = time.time()
            if now - last_time > 5:
                break

            for s in r:
                try:
                    d, addr = s.recvfrom(2048)
                except (ConnectionResetError, ConnectionRefusedError):
                    #
                    # 同时向多个ip发送消息时，部分ip可能会回复ICMP Port Unreachable
                    # 导致socket接收异常，忽略即可，不影响后续收发
                    #
                    logging.warning(f"Skip ICMP port unreachable warning")
                    continue

                t, p, left = libs.packet_unpack(d)
                assert not left

                if t == libs.PacketHeader.heartbeat:
                    h = p.decode().split(":")
                    if len(h) == 3:
                        resp_addr = addr
                        if h[0] == "SYNC":
                            ws.append(s)
                        elif h[0] == "ACK":
                            local_vpn_ok = True
                            s.connect(resp_addr)
                            logging.info(
                                "Local VPN build ok!(%s:%d=>%s:%d)",
                                local_addr[0], local_addr[1], resp_addr[0], resp_addr[1])
                            break

            if s in w:
                tag = "SYNC" if not resp_addr else "ACK"
                content = f"{tag}:0:{time.time()}".encode()
                d = libs.packet_pack(
                    content, libs.PacketHeader.heartbeat)

                if not resp_addr:
                    for ip, _ in peer_ipv4:
                        s.sendto(d, (ip, peer_local[1]))
                else:
                    s.connect(resp_addr)
                    s.send(d)
                    local_vpn_ok = True
                    logging.info(
                        "Local VPN build ok!(%s:%d=>%s:%d)",
                        local_addr[0], local_addr[1], resp_addr[0], resp_addr[1])
                    break

            if not r and not w:
                ws.append(s)

    if local_vpn_ok:
        if conf.p2p_test:
            test_throughput(s, 30)
            logging.info("P2P throught test finish!")
            return

        vpn_tunnel_mgr.is_tcp = False
        vpn_tunnel_mgr.is_p2p = True
        tun = (conf.vip, conf.vmask, conf.mtu)
        with VPN(conf.instance_id, tun, s,
                 vpn_tunnel_mgr, conf.show_status, conf.tun_handle) as v:
            v.run()
        return
    else:
        s.close()

    logging.info(f"Begin building NAT-Tunnel...")
    s = None

    method, tcp_last_delay, udp_last_delay = vpn_tunnel_mgr.p2p_preferd_method()

    def tcp_p2p_tunnel_build():
        nonlocal s
        if s:
            return s

        if tcp_last_delay >= vpn_tunnel_mgr.delay_max:
            return None

        # 1. try tcp p2p
        for t in range(3):
            #
            # @note: 多次重试说明
            #   由于tcp限制更严格，两端发起打洞先后次序决定是否成功，所以需要尝试多次
            #
            s = nat_tunnel_build_tcp(conf, token)
            if s:
                vpn_tunnel_mgr.is_tcp = True
                vpn_tunnel_mgr.is_p2p = True
                return s
            logging.warning(f"NAT TCP tunnel connect {t + 1}/{3} timeout")

        logging.error("NAT TCP Tunnel build timeout!")
        return None

    def udp_p2p_tunnel_build():
        nonlocal s
        if s:
            return s

        if udp_last_delay >= vpn_tunnel_mgr.delay_max:
            return None

        s = nat_tunnel_build_udp(conf, token)
        if s:
            vpn_tunnel_mgr.is_tcp = False
            vpn_tunnel_mgr.is_p2p = True
            return s
        else:
            logging.error("NAT TCP Tunnel build timeout!")
        return None

    if method == "tcp":
        tcp_p2p_tunnel_build()
        udp_p2p_tunnel_build()
    else:
        udp_p2p_tunnel_build()
        tcp_p2p_tunnel_build()

    # 3. try tcp forward
    if not s:
        s = nat_tunnel_build_tcp(conf, token, True)
        if s:
            vpn_tunnel_mgr.is_tcp = True
            vpn_tunnel_mgr.is_p2p = False

    # 4. try udp forward
    if not s:
        logging.error("TCP forward build timeout!")
        s = nat_tunnel_build_udp(conf, token, True)
        if s:
            vpn_tunnel_mgr.is_tcp = False
            vpn_tunnel_mgr.is_p2p = False

    if not s:
        logging.error("UDP forward build timeout!")
        return

    if conf.p2p_test:
        test_throughput(s, 30)
        logging.info("P2P throught test finish!")
        return

    tun = (conf.vip, conf.vmask, conf.mtu)
    with VPN(conf.instance_id, tun, s,
             vpn_tunnel_mgr, conf.show_status, conf.tun_handle) as v:
        v.run()


def vpn_main(argv=None, tun_handle=None):
    conf = parse_args(argv)
    set_loggint_format(conf)

    setattr(conf, 'instance_id', libs.device_id())
    setattr(conf, 'tun_handle', tun_handle)

    fail_try_time = 0
    wait_time = 5
    while True:
        normal_exit = False
        try:
            t = time.time()
            if conf.cs_vpn:
                setup_cs_vpn(conf)
            else:
                #
                # 运行时解析IP，防止断网退出
                #
                setattr(conf, 'server_ip', socket.gethostbyname(conf.server))
                setup_p2p_vpn(conf)
            if time.time() - t > 5:
                normal_exit = True
                # 恢复计数
                fail_try_time = 0
        except (socket.gaierror, OSError) as e:
            logging.warning("VPN instance exit(%s)", traceback.format_exc())
        except AuthCheckFailed as e:
            logging.warning("VPN instance exit(%s)", traceback.format_exc())
        except Exception as e:
            logging.error("VPN instance exit\n%s", traceback.format_exc())
            pass

        if not conf.run_as_service or conf.p2p_test:
            break

        if not normal_exit:
            if fail_try_time * wait_time > 1800:
                # 超过30分钟不恢复，恢复计数重试
                fail_try_time = 0
            else:
                fail_try_time += 1

        # 避免无限失败请求
        time.sleep((fail_try_time + 1) * wait_time)


def android_main(server, server_key, user, password, vip, tun_handle):
    '''
    由Android上层调用
    '''
    extra_argv = [
        "-s", server,
        "--server-key", server_key,
        "--user", user,
        "--passwd", password,
        "--vip", vip,
        "--verbose", "INFO",
    ]
    vpn_main(extra_argv, tun_handle)


if __name__ == '__main__':
    vpn_main()
