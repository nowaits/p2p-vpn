
import threading
import queue
import socket
import sys
import logging
import traceback
import select
import time

import libs


class VPN(object):

    def __init__(self, instance_id, tun, sock,
                 vpn_tunnel_mgr,
                 show_status, tun_handle=None):
        self._instance_id = instance_id
        self._tun = libs.TunTap(nic_type="Tun", tun_handle=tun_handle)
        self._tun.config(tun[0], tun[1], mtu=tun[2])
        assert sock != None
        self._sock = sock
        self._terminate = False
        self._show_status = show_status
        self._tun_read_queue = queue.Queue()
        self._tun_write_queue = queue.Queue()
        self._rx_rate = libs.Rate()
        self._tx_rate = libs.Rate()
        self._select_tun = not sys.platform.startswith("win")
        # 使用socket解决windows平台下，select不支持tun文件问题
        self._mock_sock = socket.socketpair()
        self._threads = []
        self._vpn_tunnel_mgr = vpn_tunnel_mgr
        self._vpn_tunnel_mgr.delay = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        assert self._terminate
        self._tun.close()
        self._sock.close()
        self._mock_sock[0].close()
        self._mock_sock[1].close()
        for t in self._threads:
            t.join(timeout=5)
        logging.info("VPN closed!")

    def _tun_read(self):
        notify = "notify".encode()
        while not self._terminate:
            try:
                p = self._tun.read(2048)
                if not p:
                    continue
                p = libs.packet_pack(p, libs.PacketHeader.data)
                self._tun_read_queue.put(p)
                # 发送socket通知，触发socket发送操作
                self._mock_sock[1].send(notify)
            except Exception as e:
                traceback.print_exc()
                pass

        logging.info("tun read thread exit!")

    def _tun_write(self):
        while not self._terminate:
            try:
                p = self._tun_write_queue.get(timeout=1)
            except Exception as e:
                continue

            try:
                self._tun.write(p)
            except Exception as e:
                traceback.print_exc()
                pass

        logging.info("tun write thread exit!")

    def _status(self):
        index = -1
        last_rx = 0
        last_tx = 0
        while not self._terminate:
            time.sleep(1)
            index += 1
            r0 = self._rx_rate.format_now()
            r1 = self._tx_rate.format_now()
            a0 = self._rx_rate.format_avg()
            a1 = self._tx_rate.format_avg()
            t0 = self._rx_rate.format_total()
            t1 = self._tx_rate.format_total()

            if last_tx == self._tx_rate.total()[0] and \
                    last_rx == self._rx_rate.total()[0] and \
                    index % 300 != 0:
                continue

            last_tx = self._tx_rate.total()[0]
            last_rx = self._rx_rate.total()[0]

            logging.info(
                "%s%s(%d) Rate(%s) "
                "RX-TX=%s/%s-%s/%s TOTAL=%s/%s Delay=%d" % (
                    "T" if self._vpn_tunnel_mgr.is_tcp else "U",
                    "P" if self._vpn_tunnel_mgr.is_p2p else "F",
                    self._vpn_tunnel_mgr.connect_time,
                    libs.format_time_diff(index),
                    r0[1], a0[1],
                    r1[1], a1[1],
                    t0[1], t1[1],
                    int(self._vpn_tunnel_mgr.delay)))

        logging.info("status thread exit!")

    def run(self):
        if self._select_tun:
            rs = [self._sock, self._tun.handle]
        else:
            rs = [self._sock, self._mock_sock[0]]
            thread = threading.Thread(target=self._tun_read)
            thread.daemon = True
            thread.start()
            self._threads.append(thread)
            thread = threading.Thread(target=self._tun_write)
            thread.daemon = True
            thread.start()
            self._threads.append(thread)

        if self._show_status:
            thread = threading.Thread(target=self._status)
            thread.daemon = True
            thread.start()
            self._threads.append(thread)
        self._last_recv_data_time = time.time()

        ws = []
        heartbeat_seq_no = 0
        peer_heartbeat_time = 0
        peer_heartbeat_seq_no = 0
        need_send_heart = False
        need_send_heart_ack = False
        last_heartbeat_time = 0
        recv_left = b''
        while not self._terminate:
            try:
                r, w, _ = select.select(rs, ws, [], 5)

                ws = []
                now = time.time()

                if now - self._last_recv_data_time > 30:
                    logging.error("Heartbeat timeout!")
                    self._terminate = True
                    break

                if not r and not w:
                    #
                    # request heartbeat if no recv data
                    #
                    #   1. 无数据时，请求发送心跳
                    #   2. 如果接收到数据，则取消心跳发送
                    #
                    need_send_heart = True
                    ws.append(self._sock)
                    continue

                if self._sock in r:
                    d = self._sock.recv(2048)
                    if not d:
                        continue

                    ok, ps, recv_left = \
                        libs.packet_unpack_all(recv_left + d)
                    if not ok:
                        raise Exception("VPN Packet stream error!")

                    for t, p in ps:
                        if t == libs.PacketHeader.data:
                            self._tun_write_queue.put(p)
                            self._rx_rate.feed(now, len(p))
                            self._last_recv_data_time = now
                            need_send_heart = False
                        elif t == libs.PacketHeader.heartbeat:
                            h = p.decode().split(":")
                            if len(h) == 3:
                                if h[0] != self._instance_id:
                                    self._last_recv_data_time = now
                                    need_send_heart = False
                                    need_send_heart_ack = True
                                    peer_heartbeat_seq_no = int(h[1])
                                    peer_heartbeat_time = float(h[2])
                                    ws.append(self._sock)
                                    logging.debug(
                                        "Heartbeat recv:%s", p.decode())
                                else:
                                    logging.warning(
                                        "Heartbeat recv:%s from self", p.decode())
                            pass
                        elif t == libs.PacketHeader.heartbeat_ack:
                            h = p.decode().split(":")
                            if len(h) == 3:
                                if h[0] != self._instance_id:
                                    self._last_recv_data_time = now
                                    need_send_heart = False
                                    need_send_heart_ack = False
                                    seq = int(h[1])
                                    if seq != 0:
                                        should_terminate, msg = self._vpn_tunnel_mgr.update_delay(
                                            # 单程时延
                                            int(1e6*(now - float(h[2]))/2)
                                        )
                                        if should_terminate:
                                            raise Exception(msg)

                                    logging.debug(
                                        "Heartbeat ack:%s", p.decode())
                                else:
                                    logging.warning(
                                        "Heartbeat ack:%s from self", p.decode())
                            pass
                        elif t == libs.PacketHeader.control:
                            logging.debug(
                                "VPN Packet control message: %s", p.decode())
                        elif t == libs.PacketHeader.invalid_type:
                            logging.warning("VPN Packet type invalid!")
                        elif t == libs.PacketHeader.need_more_data:
                            logging.info("VPN Packet need more data!")
                        else:
                            logging.error("VPN Packet type:%d unknow!", t)

                if self._tun.handle in r:
                    d = self._tun.read(2048)
                    p = libs.packet_pack(d, libs.PacketHeader.data)
                    self._tun_read_queue.put(p)

                if self._mock_sock[0] in r and self._sock in w:
                    assert not self._select_tun
                    self._mock_sock[0].recv(32)  # drop msg
                    if self._tun_read_queue.qsize() > 0:
                        p = self._tun_read_queue.get()
                        self._sock.send(p)
                        w.remove(self._sock)
                        self._tx_rate.feed(now, len(p))

                n = self._tun_read_queue.qsize()
                if n > 0:
                    if self._sock in w:
                        p = self._tun_read_queue.get()
                        self._sock.send(p)
                        w.remove(self._sock)
                        self._tx_rate.feed(now, len(p))
                        n -= 1
                    if n > 0:
                        ws.append(self._sock)

                if need_send_heart or now - last_heartbeat_time > 300:
                    # 强制5分钟发送一次心跳
                    if self._sock in w:
                        content = f"{self._instance_id}:{heartbeat_seq_no}:{now}"
                        d = libs.packet_pack(
                            content.encode(), libs.PacketHeader.heartbeat)
                        self._sock.send(d)
                        need_send_heart = False
                        heartbeat_seq_no += 1
                        last_heartbeat_time = now
                        w.remove(self._sock)
                        logging.debug(f"Send heartbeat: {content}")
                    else:
                        ws.append(self._sock)

                if need_send_heart_ack:
                    if self._sock in w:
                        content = f"{self._instance_id}:{peer_heartbeat_seq_no}:{peer_heartbeat_time}"
                        d = libs.packet_pack(
                            content.encode(), libs.PacketHeader.heartbeat_ack)
                        self._sock.send(d)
                        need_send_heart_ack = False
                        w.remove(self._sock)
                        logging.debug(f"Send heartbeat ack: {content}")
                    else:
                        ws.append(self._sock)

                if not self._select_tun:
                    continue

                n = self._tun_write_queue.qsize()
                if n > 0:
                    if self._tun.handle in w:
                        p = self._tun_write_queue.get()
                        self._tun.write(p)
                        n -= 1

                    if n > 0:
                        ws.append(self._tun.handle)
            except KeyboardInterrupt:
                self._terminate = True
                logging.info(
                    "VPN proc user canceled\n(%s)",
                    traceback.format_exc())
            except Exception:
                self._terminate = True
                logging.error(
                    "VPN proc exit\n(%s)",
                    traceback.format_exc())

        logging.info("VPN worker exit!")
