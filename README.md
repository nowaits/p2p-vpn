## p2p-vpn

基于UDP协议的p2p vpn，支持windows/linux平台，支持NAT穿越

#### 依赖

- python: `>=3.6`
    - windows平台win32运行时:`pip install pywin32 wmi`
- format: `pip3 install autopep8`
    - `autopep8 -i <xxx>.py`
- windows tap网卡安装： [Tap-Windows Adapter V9](https://github.com/OpenVPN/tap-windows6/)
    1. [github下载依赖](https://github.com/OpenVPN/tap-windows6/releases/download/9.26.0/dist.win7.zip)
    2. 解压并安装:`tapinstall.exe install OemVista.inf tap0901`
        - 注意：`需要多网卡支持时，重复执行上述命令`

### 启动

- C/S类型VPN，至少一方能访问另外一方
    - server: `python vpn --cs-vpn --vip=10.0.0.1`
    - client: `python vpn --cs-vpn -c -s=<server ip> --vip=10.0.0.2`

- NAT穿越类型VPN，需要借助公网服务器转发对方出口地址
    - 公网服务器：`python server -p=<server port>`
    - client A: `python vpn -s=<server ip> -p=<server port> --user=<name> --passwd=<passwd> --vip=10.0.0.1`
    - client B: `python vpn -s=<server ip> -p=<server port> --user=<name> --passwd=<passwd> --vip=10.0.0.2`

- 用户密码认证过程
    ```
    CLIENT A/B                                          SERVER
    ----------                                          ------
    user,ins_id,action                     --->       [record addr]
                                           <---         challenge
    user,ins_id,action,auth                --->      [check auth(A|B)]
    [auth=HMAC(challenge,user+passwd)]
                                           <---         peer_addr
    ```

- 以服务形式运行: `添加参数：--run-as-service`
- 更多参考:`python vpn -h`

### TODO

1. vpn多实例
2. 流量加密

### DOC

- python doc
    - [struct](https://docs.python.org/3/library/struct.html)
    - [types](https://docs.python.org/3/library/stdtypes.html#binary-sequence-types-bytes-bytearray-memoryview)