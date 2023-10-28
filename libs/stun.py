import binascii
import logging
import random
import socket
import sys

__version__ = '0.1.0'

log = logging.getLogger("pystun")


stun_servers_list = (
    ("stun.internetcalls.com", 3478),
    ("stun.voip.aebc.com", 3478),
    ("stun1.l.google.com", 5432),
    ("stun2.l.google.com", 5432),
    ("stun3.l.google.com", 5432),
    ("stun4.l.google.com", 5432),
    ("stun.ekiga.net", 3478),
    ("stun.ideasip.com", 3478),
    ("stun.schlund.de", 3478),
    ("stun.stunprotocol.org", 3478),
    ("stun.voiparound.com", 3478),
    ("stun.voipbuster.com", 3478),
    ("stun.voipstunt.com", 3478),
    ("stun.voxgratia.org", 3478),
    ("stun.services.mozilla.com", 3478)
)

DEFAULTS = {
    'stun_port': 3478,
    'source_ip': '0.0.0.0',
    'source_port': 54320
}

# stun attributes
MappedAddress = '0001'
ResponseAddress = '0002'
ChangeRequest = '0003'
SourceAddress = '0004'
ChangedAddress = '0005'
Username = '0006'
Password = '0007'
MessageIntegrity = '0008'
ErrorCode = '0009'
UnknownAttribute = '000A'
ReflectedFrom = '000B'
XorOnly = '0021'
XorMappedAddress = '8020'
ServerName = '8022'
SecondaryAddress = '8050'  # Non standard extension

# types for a stun message
BindRequestMsg = '0001'
BindResponseMsg = '0101'
BindErrorResponseMsg = '0111'
SharedSecretRequestMsg = '0002'
SharedSecretResponseMsg = '0102'
SharedSecretErrorResponseMsg = '0112'

dictAttrToVal = {'MappedAddress': MappedAddress,
                 'ResponseAddress': ResponseAddress,
                 'ChangeRequest': ChangeRequest,
                 'SourceAddress': SourceAddress,
                 'ChangedAddress': ChangedAddress,
                 'Username': Username,
                 'Password': Password,
                 'MessageIntegrity': MessageIntegrity,
                 'ErrorCode': ErrorCode,
                 'UnknownAttribute': UnknownAttribute,
                 'ReflectedFrom': ReflectedFrom,
                 'XorOnly': XorOnly,
                 'XorMappedAddress': XorMappedAddress,
                 'ServerName': ServerName,
                 'SecondaryAddress': SecondaryAddress}

dictMsgTypeToVal = {
    'BindRequestMsg': BindRequestMsg,
    'BindResponseMsg': BindResponseMsg,
    'BindErrorResponseMsg': BindErrorResponseMsg,
    'SharedSecretRequestMsg': SharedSecretRequestMsg,
    'SharedSecretResponseMsg': SharedSecretResponseMsg,
    'SharedSecretErrorResponseMsg': SharedSecretErrorResponseMsg}

dictValToMsgType = {}

dictValToAttr = {}

Blocked = "Blocked"
OpenInternet = "Open Internet"
FullCone = "Full Cone"
SymmetricUDPFirewall = "Symmetric UDP Firewall"
RestricNAT = "Restric NAT"
RestricPortNAT = "Restric Port NAT"
SymmetricNAT = "Symmetric NAT"
ChangedAddressError = "Meet an error, when do Test1 on Changed IP and Port"


def _initialize():
    for k, v in dictAttrToVal.items():
        dictValToAttr.update({v: k})
    for k, v in dictMsgTypeToVal.items():
        dictValToMsgType.update({v: k})


def gen_tran_id():
    a = ''.join(random.choice('0123456789ABCDEF') for i in range(32))
    # return binascii.a2b_hex(a)
    return a


def stun_test(sock, host, port, source_ip, source_port, send_data=""):
    retVal = {'Resp': False, 'ExternalIP': None, 'ExternalPort': None,
              'SourceIP': None, 'SourcePort': None, 'ChangedIP': None,
              'ChangedPort': None}
    str_len = "%#04d" % (len(send_data) / 2)
    tranid = gen_tran_id()
    str_data = ''.join([BindRequestMsg, str_len, tranid, send_data])
    data = binascii.a2b_hex(str_data)
    recvCorr = False
    while not recvCorr:
        recieved = False
        count = 3
        while not recieved:
            log.debug("sendto: %s", (host, port))
            try:
                sock.sendto(data, (host, port))
            except socket.gaierror:
                retVal['Resp'] = False
                return retVal
            try:
                buf, addr = sock.recvfrom(2048)
                log.debug("recvfrom: %s", addr)
                recieved = True
            except Exception:
                recieved = False
                if count > 0:
                    count -= 1
                else:
                    retVal['Resp'] = False
                    return retVal
        msgtype = binascii.b2a_hex(buf[0:2]).decode()
        bind_resp_msg = dictValToMsgType[msgtype] == "BindResponseMsg"
        tranid_match = tranid.upper() == binascii.b2a_hex(
            buf[4:20]).upper().decode()
        if bind_resp_msg and tranid_match:
            recvCorr = True
            retVal['Resp'] = True
            len_message = int(binascii.b2a_hex(buf[2:4]), 16)
            len_remain = len_message
            base = 20
            while len_remain:
                attr_type = binascii.b2a_hex(buf[base:(base + 2)]).decode()
                attr_len = int(binascii.b2a_hex(
                    buf[(base + 2):(base + 4)]), 16)
                if attr_type == MappedAddress:
                    port = int(binascii.b2a_hex(buf[base + 6:base + 8]), 16)
                    ip = ".".join([
                        str(int(binascii.b2a_hex(buf[base + 8:base + 9]), 16)),
                        str(int(binascii.b2a_hex(
                            buf[base + 9:base + 10]), 16)),
                        str(int(binascii.b2a_hex(
                            buf[base + 10:base + 11]), 16)),
                        str(int(binascii.b2a_hex(
                            buf[base + 11:base + 12]), 16))
                    ])
                    retVal['ExternalIP'] = ip
                    retVal['ExternalPort'] = port
                if attr_type == SourceAddress:
                    port = int(binascii.b2a_hex(buf[base + 6:base + 8]), 16)
                    ip = ".".join([
                        str(int(binascii.b2a_hex(buf[base + 8:base + 9]), 16)),
                        str(int(binascii.b2a_hex(
                            buf[base + 9:base + 10]), 16)),
                        str(int(binascii.b2a_hex(
                            buf[base + 10:base + 11]), 16)),
                        str(int(binascii.b2a_hex(
                            buf[base + 11:base + 12]), 16))
                    ])
                    retVal['SourceIP'] = ip
                    retVal['SourcePort'] = port
                if attr_type == ChangedAddress:
                    port = int(binascii.b2a_hex(buf[base + 6:base + 8]), 16)
                    ip = ".".join([
                        str(int(binascii.b2a_hex(buf[base + 8:base + 9]), 16)),
                        str(int(binascii.b2a_hex(
                            buf[base + 9:base + 10]), 16)),
                        str(int(binascii.b2a_hex(
                            buf[base + 10:base + 11]), 16)),
                        str(int(binascii.b2a_hex(
                            buf[base + 11:base + 12]), 16))
                    ])
                    retVal['ChangedIP'] = ip
                    retVal['ChangedPort'] = port
                if attr_type == ServerName:
                    serverName = buf[(base+4):(base+4+attr_len)]
                base = base + 4 + attr_len
                len_remain = len_remain - (4 + attr_len)
    # s.close()
    return retVal


def get_nat_type(s, source_ip, source_port, stun_host, stun_port):
    _initialize()
    log.debug("Do Test1")
    resp = False
    if stun_host:
        ret = stun_test(s, stun_host, stun_port, source_ip, source_port)
        resp = ret['Resp']
    else:
        for stun_host, stun_port in stun_servers_list:
            log.debug('Trying STUN host: %s:%d', stun_host, source_port)
            ret = stun_test(s, stun_host, stun_port, source_ip, source_port)
            resp = ret['Resp']
            if resp:
                break
    if not resp:
        return Blocked, ret
    log.debug("Result: %s", ret)
    exIP = ret['ExternalIP']
    exPort = ret['ExternalPort']
    changedIP = ret['ChangedIP']
    changedPort = ret['ChangedPort']
    if ret['ExternalIP'] == source_ip:
        changeRequest = ''.join([ChangeRequest, '0004', "00000006"])
        ret = stun_test(s, stun_host, stun_port, source_ip, source_port,
                        changeRequest)
        if ret['Resp']:
            typ = OpenInternet
        else:
            typ = SymmetricUDPFirewall
    else:
        changeRequest = ''.join([ChangeRequest, '0004', "00000006"])
        log.debug("Do Test2")
        ret = stun_test(s, stun_host, stun_port, source_ip, source_port,
                        changeRequest)
        log.debug("Result: %s", ret)
        if ret['Resp']:
            typ = FullCone
        else:
            log.debug("Do Test1")
            ret = stun_test(s, changedIP, changedPort, source_ip, source_port)
            log.debug("Result: %s", ret)
            if not ret['Resp']:
                typ = ChangedAddressError
            else:
                if exIP == ret['ExternalIP'] and exPort == ret['ExternalPort']:
                    changePortRequest = ''.join([ChangeRequest, '0004',
                                                 "00000002"])
                    log.debug("Do Test3")
                    ret = stun_test(s, changedIP, stun_port, source_ip, source_port,
                                    changePortRequest)
                    log.debug("Result: %s", ret)
                    if ret['Resp']:
                        typ = RestricNAT
                    else:
                        typ = RestricPortNAT
                else:
                    typ = SymmetricNAT
    return typ, ret


def get_ip_info(source_ip="0.0.0.0", source_port=56731, stun_host=None, stun_port=3478):
    socket.setdefaulttimeout(2)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    while True:
        try:
            s.bind((source_ip, source_port))
            break
        except PermissionError as e:
            log.debug("Port:%d used, try: %d",
                    source_port, source_port + 1)
            source_port += 1
            pass
    nat_type, nat = get_nat_type(
        s, source_ip, source_port, stun_host, stun_port)
    external_ip = nat['ExternalIP']
    external_port = nat['ExternalPort']
    s.close()
    return (source_ip, source_port, nat_type, external_ip, external_port)

if __name__ == '__main__':
    debug_info = " %(filename)s %(funcName)s:%(lineno)d "

    logging.basicConfig(
        level=logging.DEBUG,
        stream=sys.stdout,
        format='[%(asctime)s %(levelname)s' + debug_info + ']: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    source_ip, source_port, nat_type, external_ip, external_port = get_ip_info()
    print("source-ip:", source_ip)
    print("source-port:", source_port)
    print("nat-type:", nat_type)
    print("external ip:", external_ip)
    print("external port:", external_port)
