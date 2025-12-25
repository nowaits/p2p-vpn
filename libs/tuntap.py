import unittest
import struct

import subprocess
import sys
import socket
import time
from _thread import start_new_thread
import logging
import os
import math

if sys.platform.startswith("win"):
    import win32file
    import pywintypes
    import win32event
    import wmi
else:
    import fcntl


class Packet(object):
    def __init__(self, data=None, frame=None):
        if frame:
            self.load(frame)
            return
        if data:
            self.data = data

    def load(self, frame):
        self.data = frame[12+2:]

    def get_version(self):
        return self.data[0] >> 4

    def get_src(self):
        return self.data[12:16]

    def get_dst(self):
        return self.data[16:20]


def TunTap(nic_type, fd=None):
    if sys.platform.startswith("win"):
        tap = WinTap(nic_type)
    elif sys.platform.startswith("android"):
        tap = AndroidTap(nic_type, fd)
    else:
        tap = Tap(nic_type)
    tap.create()
    return tap


class Tap(object):
    def __init__(self, nic_type):
        self.nic_type = nic_type
        self.mac = b"\x00"*6
        self.handle = None
        self.ip = None
        self.mask = None
        self.gateway = None
        self.quitting = False

    def create(self):
        TUNSETIFF = 0x400454ca
        IFF_TUN = 0x0001
        IFF_TAP = 0x0002
        IFF_NO_PI = 0x1000
        self.handle = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
        if not self.handle:
            return None
        if self.nic_type == "Tap":
            flags = IFF_TAP | IFF_NO_PI
        if self.nic_type == "Tun":
            flags = IFF_TUN | IFF_NO_PI
            ifr_name = b'\x00'*16
        ifr = struct.pack('16sH22s', ifr_name, flags, b'\x00'*22)
        ret = fcntl.ioctl(self.handle, TUNSETIFF, ifr)
        dev, _ = struct.unpack('16sH', ret[:18])
        dev = dev.decode().strip("\x00")
        self.name = dev
        logging.info(f"device {self.name} opened")
        return self

    def _get_maskbits(self, mask):
        masks = mask.split(".")
        maskbits = 0
        if len(masks) == 4:
            for i in range(4):
                nbit = math.log(256-int(masks[i]), 2)
                if nbit == int(nbit):
                    maskbits += 8-nbit
                else:
                    return
        return int(maskbits)

    def config(self, ip, mask, gateway="0.0.0.0", mtu=1400):
        self.ip = ip
        self.mask = mask
        self.gateway = gateway
        nmask = self._get_maskbits(self.mask)
        try:
            subprocess.check_call('ip link set '+self.name+' up', shell=True)
            subprocess.check_call(
                'ip link set '+self.name+' mtu %d' % mtu, shell=True)
            subprocess.check_call('ip addr add '+self.ip+'/%d ' %
                                  nmask + " dev " + self.name, shell=True)
        except:
            logging.warning("error when config")
            return self
        return self

    def close(self):
        self.quitting = False
        os.close(self.handle)

    def read(self, size=1522):
        return os.read(self.handle, size)

    def write(self, data):
        try:
            return os.write(self.handle, data)
        except:
            return 0

class AndroidTap(object):
    def __init__(self, nic_type, fd):
        self.nic_type = nic_type
        self.handle = fd

    def create(self):
        return self

    def _get_maskbits(self, mask):
        #TOMO: android上层需要增加mask对应底层, 支持配置
        return 24

    def config(self, ip, mask, gateway="0.0.0.0", mtu=1400):
        return self

    def close(self):
        self.quitting = False
        os.close(self.handle)

    def read(self, size=1522):
        return os.read(self.handle, size)

    def write(self, data):
        try:
            return os.write(self.handle, data)
        except:
            return 0

class WinTap(Tap):
    def __init__(self, nic_type):
        super().__init__(nic_type)
        self._nic = None
        self.TAP_IOCTL_GET_MAC = self._TAP_CONTROL_CODE(1, 0)
        self.TAP_IOCTL_GET_VERSION = self._TAP_CONTROL_CODE(2, 0)
        self.TAP_IOCTL_GET_MTU = self._TAP_CONTROL_CODE(3, 0)
        self.TAP_IOCTL_GET_INFO = self._TAP_CONTROL_CODE(4, 0)
        self.TAP_IOCTL_CONFIG_POINT_TO_POINT = self._TAP_CONTROL_CODE(5, 0)
        self.TAP_IOCTL_SET_MEDIA_STATUS = self._TAP_CONTROL_CODE(6, 0)
        self.TAP_IOCTL_CONFIG_DHCP_MASQ = self._TAP_CONTROL_CODE(7, 0)
        self.TAP_IOCTL_GET_LOG_LINE = self._TAP_CONTROL_CODE(8, 0)
        self.TAP_IOCTL_CONFIG_DHCP_SET_OPT = self._TAP_CONTROL_CODE(9, 0)

        self.TAP_IOCTL_CONFIG_TUN = self._TAP_CONTROL_CODE(10, 0)

        self.read_overlapped = pywintypes.OVERLAPPED()
        eventhandle = win32event.CreateEvent(None, True, False, None)
        self.read_overlapped.hEvent = eventhandle
        self.write_overlapped = pywintypes.OVERLAPPED()
        eventhandle = win32event.CreateEvent(None, True, False, None)
        self.write_overlapped.hEvent = eventhandle
        self.buffer = win32file.AllocateReadBuffer(2000)

    def _CTL_CODE(self, device_type, function, method, access):
        return (device_type << 16) | (access << 14) | (function << 2) | method

    def _TAP_CONTROL_CODE(self, request, method):
        return self._CTL_CODE(34, request, method, 0)

    def _mac2string(self, mac):
        mac_string = ""
        for i in range(len(mac)):
            mac_string += "%02X" % mac[i]
            if i < len(mac)-1:
                mac_string += "-"
        return mac_string

    def create(self):
        c = wmi.WMI()
        devices = []
        for nic in c.Win32_NetworkAdapter():
            '''
            instance of Win32_NetworkAdapter
            {
                AdapterType = "以太网 802.3";
                AdapterTypeId = 0;
                Availability = 3;
                Caption = "[00000019] TAP-Windows Adapter V9";
                ConfigManagerErrorCode = 0;
                ConfigManagerUserConfig = FALSE;
                CreationClassName = "Win32_NetworkAdapter";
                Description = "TAP-Windows Adapter V9";
                DeviceID = "19";
                GUID = "{7676C11C-9588-460D-B8A6-53397AF52491}";
                Index = 19;
                Installed = TRUE;
                InterfaceIndex = 13;
                MACAddress = "00:FF:76:76:C1:1C";
                Manufacturer = "TAP-Windows Provider V9";
                MaxNumberControlled = 0;
                Name = "TAP-Windows Adapter V9";
                NetConnectionID = "本地连接 2";
                NetConnectionStatus = 0;
                NetEnabled = FALSE;
                PhysicalAdapter = TRUE;
                PNPDeviceID = "ROOT\\NET\\0001";
                PowerManagementSupported = FALSE;
                ProductName = "TAP-Windows Adapter V9";
                ServiceName = "tap0901";
                Speed = "1000000000";
                SystemCreationClassName = "Win32_ComputerSystem";
                SystemName = "DESKTOP-QPIHHFU";
                TimeOfLastReset = "20251003095941.500000+480";
            };
            '''
            if nic.ServiceName != "tap0901":
                continue

            # 手动禁用
            if nic.ConfigManagerErrorCode == 22:
                continue

            # 已经使用
            if nic.NetEnabled:
                continue

            devices.append(nic)

            try:
                #
                # 通过启用dhcp删除已经存在IP，此时设备可能已经被其它设备打开，但是还未配置，可以放心删除IP
                #
                subprocess.check_call(
                    f"netsh interface ip set address name=\"{nic.NetConnectionID}\" dhcp",
                    shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError as e:
                if e.returncode != 1:  # 已经配置过
                    raise

        if not devices:
            return

        for d in devices:
            self.handle = win32file.CreateFile(
                "\\\\.\\Global\\%s.tap" % d.GUID,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None, win32file.OPEN_EXISTING,
                win32file.FILE_ATTRIBUTE_SYSTEM | win32file.FILE_FLAG_OVERLAPPED, None)
            if not self.handle:
                continue

            self._nic = {
                "name": d.NetConnectionID,
                "mac": d.MACAddress,
            }
            self.name = self._nic["name"]
            break

        if not self._nic:
            raise Exception("not free TAP-Windows Adapter V9 found!")

        logging.info(f"device {self.name} opened")

    def config(self, ip, mask, gateway="0.0.0.0", mtu=1400):
        self.ip = ip
        self.mask = mask
        self.gateway = gateway

        try:
            code = b'\x01\x00\x00\x00'
            win32file.DeviceIoControl(
                self.handle, self.TAP_IOCTL_SET_MEDIA_STATUS, code, 512, None)
            ipnet = struct.pack("I", struct.unpack("I", socket.inet_aton(self.ip))[
                                0] & struct.unpack("I", socket.inet_aton(self.mask))[0])
            ipcode = socket.inet_aton(self.ip)+ipnet + \
                socket.inet_aton(self.mask)
            if self.nic_type == "Tap":
                flag = self.TAP_IOCTL_CONFIG_POINT_TO_POINT
            if self.nic_type == "Tun":
                flag = self.TAP_IOCTL_CONFIG_TUN
            win32file.DeviceIoControl(
                self.handle, flag, ipcode, 16, None)
        except Exception as exp:
            logging.debug(exp)
            win32file.CloseHandle(self.handle)

        cmd = f"netsh interface ip set address name=\"{self.name}\" source=static addr={self.ip} mask={self.mask}"

        if self.gateway != "0.0.0.0":
            cmd += " gateway={self.gateway}"
        try:
            subprocess.check_call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError as e:
            if e.returncode != 1:  # 忽略已存在警告
                raise

        cmd = f"netsh interface ipv4 set subinterface \"{self.name}\" mtu={mtu} store=persistent"
        subprocess.check_call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def read(self, size=1522):
        try:
            win32event.ResetEvent(self.read_overlapped.hEvent)
            err, data = win32file.ReadFile(
                self.handle, self.buffer, self.read_overlapped)
            if err == 997:  # ERROR_IO_PENDING
                n = win32file.GetOverlappedResult(
                    self.handle, self.read_overlapped, True)

                return bytes(data[:n])
            else:
                return bytes(data)
        except Exception as e:
            return None
            pass

    def write(self, data):
        win32event.ResetEvent(self.write_overlapped.hEvent)
        err, writelen = win32file.WriteFile(
            self.handle, data, self.write_overlapped)
        if err == 997:
            return win32file.GetOverlappedResult(
                self.handle, self.write_overlapped, True)
        else:
            return writelen

    def close(self):
        win32file.CloseHandle(self.handle)


class Test(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def readtest(self, tap):
        while not tap.quitting:
            p = tap.read()
            print("rawdata:", ''.join('{:02x} '.format(x) for x in p))
            if not p:
                continue
            if tap.nic_type == "Tap":
                packet = Packet(frame=p)
            else:
                packet = Packet(data=p)
            if not packet.get_version() == 4:
                continue
            print('packet:', "".join('{:02x} '.format(x) for x in packet.data))

    def testTap(self):
        tap = TunTap(nic_type="Tap")
        tap.config("192.168.2.82", "255.255.255.0")
        print(tap.name)
        start_new_thread(self.readtest, (tap,))
        s = input("press any key to quit!")
        tap.quitting = True
        time.sleep(1)
        tap.close()
        pass

    def testTun(self):
        tap = TunTap(nic_type="Tun")
        tap.config("192.168.2.82", "255.255.255.0")
        print(tap.name)
        start_new_thread(self.readtest, (tap,))
        s = input("press any key to quit!")
        tap.quitting = True
        time.sleep(2)
        tap.close()
        pass


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    #     unittest.main()

    suite = unittest.TestSuite()
    if len(sys.argv) == 1:
        suite = unittest.TestLoader().loadTestsFromTestCase(Test)
    else:
        for test_name in sys.argv[1:]:
            print(test_name)
            suite.addTest(Test(test_name))

    unittest.TextTestRunner(verbosity=2).run(suite)