import ping3
import socket
from aiohttp_socks import ProxyConnector
import asyncio
import aiohttp
import time
import os
import re
import urllib.parse
from urllib.parse import unquote
import json
import subprocess
import base64
from urllib.parse import urlparse, parse_qs
import requests
requests.packages.urllib3.disable_warnings()
import aioping





import time

# 封装异步ping函数



async def ping(ip, max_retries=3):
    for i in range(max_retries):
        try:
            delay = await aioping.ping(ip)
            return delay
        except TimeoutError:
            print(f'Ping {ip} timeout (retry {i+1})')
    return None



def parse_subscribe_url(url, need_proxy=False):
    # # 创建 session 对象
    proxy_host = '127.0.0.1'
    proxy_port = 7890
    session = requests.Session()
    if need_proxy:
        session.proxies = {
            'http': f'socks5://{proxy_host}:{proxy_port}',
            'https': f'socks5://{proxy_host}:{proxy_port}'
        }

    # 获取订阅内容
    response = session.get(url, verify=False)
    content = base64.b64decode(response.content).decode('utf-8')
    # 解析订阅内容
    node_list = []
    for line in content.splitlines():
        if line.startswith('vmess://'):
            data = base64.b64decode(line[len('vmess://'):]).decode('utf-8')
            # 输出服务器地址、端口、加密方式、密码等信息
            data_json = json.loads(data)
            config = {
                "protocol": 'vmess',
                "v": data_json.get('v'),
                "ps": data_json.get('ps'),
                "add": data_json.get('add'),
                "port": int(data_json.get('port')),
                "id": data_json.get('id'),
                "aid": data_json.get('aid'),
                "net": data_json.get('net'),
                "type": data_json.get('type'),
                "host": data_json.get('host'),
                "path": data_json.get('path'),
                "tls": data_json.get('tls'),
            }
            print(config)
            node_list.append(config)
        elif line.startswith('ss://'):
            encode_str = line.split("@")[0][5:]
            encode_str = encode_str.replace("-", "+").replace("_", "/")
            encode_str += "=" * (4 - len(encode_str) % 4)
            # 解析备注信息
            remarks = unquote(line.split("#")[1])
            password = base64.b64decode(encode_str).decode().split(":")[-1]
            method = base64.b64decode(encode_str).decode().split(":")[0]
            # 解析服务器地址和端口号
            server_address, server_port = line.split("@")[-1].split(":")
            if "#" in server_port:
                server_port = server_port.split("#")[0]
            # 输出配置信息
            config = {
                "protocol": 'ss',
                "server": server_address,
                "server_port": int(server_port),
                "password": password,
                "method": method,
                "remarks": remarks,
            }
            print(config)
            node_list.append(config)
        elif line.startswith('trojan://'):
            parsed_url = urllib.parse.urlparse(line)
            # 获取协议类型
            protocol = parsed_url.scheme
            # 获取唯一标识符
            uuid = parsed_url.username
            # 获取服务器地址和端口号
            server, port = parsed_url.hostname, parsed_url.port
            # 获取链接备注信息
            remarks = urllib.parse.unquote(parsed_url.fragment)
            remarks = re.sub(r'^.*:', '', remarks)
            # 解析查询参数
            query_params = urllib.parse.parse_qs(parsed_url.query)
            allow_insecure = int(query_params.get('allowInsecure', ['0'])[0])
            # tls_sni = parse_qs(parsed_url.query)["sni"][0]
            config = {
                'protocol': protocol,
                'uuid': uuid,
                'server': server,
                'server_port': port,
                'remarks': remarks,
                'allow_insecure': bool(allow_insecure),
                "tls_sni": ""
            }
            print(config)
            node_list.append(config)
    return node_list


def generate_config_json(nodes, path):
    outbounds = []
    inbounds = []
    rules = []

    # 遍历解析后的内容，提取参数并组织成字典格式
    for i, item in enumerate(nodes):

        if item["protocol"] == "vmess":
            outbound_dict = {
                "tag": f"socks{i+1}",
                "protocol": item["protocol"],
                "settings": {
                    "vnext": [{
                        "address": item["add"],
                        "port": item["port"],
                        "users": [{
                            "id": item["id"],
                            "alterId": item.get("alterId", 0),
                            "security": item.get("method", "auto")
                        }]
                    }]
                },
                "streamSettings": {
                    "network": "tcp"
                },
                "mux": {
                    "enabled": True,
                    "concurrency": 8
                }
            }
            outbounds.append(outbound_dict)
        elif item["protocol"] == "ss":
            outbound_dict = {
                "tag": f"socks{i+1}",
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": item["server"],
                        "method": item["method"],
                        "password": item["password"],
                        "port": item["server_port"],
                        "level": 1,
                        "ota": False
                    }]
                },
                "streamSettings": {
                    "network": "tcp"
                },
                "mux": {
                    "enabled": False,
                    "concurrency": -1
                }
            }
            outbounds.append(outbound_dict)
        # elif item["protocol"] == "trojan":
        #     if item["server_port"] > 1000:

        #         outbound_dict = {
        #             "tag": f"socks{i+1}",
        #             "protocol": "trojan",
        #             "settings": {
        #                 "servers": [
        #                     {
        #                         "address": item["server"],
        #                         "port": item["server_port"],
        #                         "password": item["uuid"],
        #                         "level": 0,
        #                         "email": ""
        #                     }
        #                 ],
        #                 "domainStrategy": "UseIP",
        #                 "allowInsecure": True
        #             },
        #             "streamSettings": {
        #                 "network": "tcp",
        #                 "security": "tls",
        #                 "tlsSettings": {
        #                     "serverName": item["tls_sni"],
        #                     "allowInsecure": True
        #                 }
        #             }
        #         }
        #         outbounds.append(outbound_dict)

        # 添加inbounds
        inbound_dict = {
            "tag": f"socks{i+1}",
            "port": 21509 + i * 2,
            "listen": "0.0.0.0",
            "protocol": "socks",
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls"],
                "routeOnly": False
            },
            "settings": {
                "auth": "noauth",
                "udp": True,
                "allowTransparent": False
            }
        }
        inbounds.append(inbound_dict)
        rule_dict = {
            "type": "field",
            "inboundTag": [
                f"socks{i+1}",
            ],
            "outboundTag": f"socks{i+1}",
            "enabled": True
        }
        rules.append(rule_dict)
    config = {
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "rules": rules
        }
    }
    # 写入到config.json文件中
    with open(os.path.join(path, "config.json"), "w", encoding="utf-8") as f:
        json.dump(config, f)

    return config

# async def check_proxy(tag, proxy_host, proxy_port)


async def check_proxy(tag, proxy_host, proxy_port, protocol, address, port, method):
    # v2ray_path = os.path.join(os.getcwd(), "Xray")
    # config = generate_config_json(node_list, v2ray_path)

    available = True
    proxy_url = f'socks5://{proxy_host}:{proxy_port}'
    ip_content = ''
    data = ''
    risk = ''
    score = ''
    rr = ''

    # 获取ip地址
    try:
        connector = ProxyConnector.from_url(proxy_url)
        async with aiohttp.ClientSession(connector=connector) as session:
            # 在请求时指定 connector 参数
            async with session.get('http://myip.ipip.net/', ssl=False, timeout=10) as response:

                ip_content = await response.text()
    except Exception as e:
        # print("--------str(e)---------")
        print(str(e))
        # print("--------str(e)---------")
        print(f'{tag}代理无法使用------获取ip地址:{ip_content}')
        available = False
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    ip_address = ''
    match = re.search(ip_pattern, ip_content)
    if match:
        ip_address = match.group()
        # print("获取ip地址")
        print(f'{tag}-----{ip_address}获取ip地址-------------')

 # 增加IP风险检测
    risk = ""
    score = ""
    if available:
        try:
            connector = ProxyConnector.from_url(proxy_url)
            async with aiohttp.ClientSession(connector=connector) as session:
                # 在请求时指定 connector 参数
                async with session.get('http://ip234.in/f.json', ssl=False, timeout=10) as response:
                    rr = await response.text()
                    rr_data = json.loads(rr)['data']
                    risk = rr_data['risk']
                    score = rr_data['score']
                    # print(f'risk: {risk}, score: {score}')
                    print(f"------{rr}---------rr----------")
                    # print(rr)
                    # 解析响应内容并获取相关信息

        except Exception as e:
            # print("--------str(e)--111-------")
            print(str(e))
            # print("--------str(e)----111-----")
            print(f'{tag}代理无法使用---{rr}---风险检测')

            available = False



    # 获取延迟
    response_time = ''
    if available:
        delay = await ping(ip_address)
        if delay is not None:
            response_time = f'{delay * 10:.2f} ms'
        else:
            response_time = 'Timeout'
        time.sleep(1)


    # # 获取延迟
    # response_time = ''
    # if available:
    #     try:
    #         response_time = int(ping3.ping(ip_address)*1000)
    #         time.sleep(1)
    #     except Exception as e:
    #         pass
    
    
    
    # 测速
    # download_speed = ''
    # if available:
    #    # test_url = 'http://cachefly.cachefly.net/100mb.test'
    #     test_url = 'https://dl.google.com/dl/android/studio/install/3.4.1.0/android-studio-ide-183.5522156-windows.exe'

    #     try:
    #         connector = ProxyConnector.from_url(proxy_url)
    #         async with aiohttp.ClientSession(connector=connector) as session:
    #             # 在请求时指定 connector 参数
    #             async with session.head(test_url, ssl=False, timeout=15) as response:
    #                 if response.status == 200:
    #                     start_time = time.time()
    #                     async with session.get(test_url) as data:
    #                         content_length = int(
    #                             data.headers.get('content-length', 0))
    #                         elapsed_time = time.time() - start_time
    #                         download_speed = content_length / elapsed_time / 1024 / 1024 / 8
    #     except Exception as e:
    #         # print(str(e))
    #         pass
    # if download_speed:
    #     download_speed = f'{download_speed:.2f} MB/s'
    #     time.sleep(1)

    if available:
        info = {
            "tag": tag,
            "protocol": protocol,
            "address": address,
            "port": port,
            "method": method,
            "风险评估": risk, "分数": score,
            "ip": ip_content,
            "延迟": f"{response_time} ",
            #"下载速度": f"{download_speed}"
        }
        with open('result.txt', 'a', encoding='utf-8') as f:
            f.write(str(info) + '\n')
        print("--------------------------------------------------------------------------")
        print(info)

 
async def check_proxy_list(inbounds, outbounds):
    proxy_host = '127.0.0.1'
    tasks = []
    address = ""
    port = ""
    protocol = ""
    method = ""

    for inbound in inbounds:
        proxy_port = inbound['port']
        tag = inbound['tag']
        for outbound in outbounds:
            if outbound['tag'] == inbound['tag']:
                protocol = outbound["protocol"]
                print("--------protocol----------")
                print(protocol)
                if protocol == "vmess":
                    address = outbound["settings"]["vnext"][0]["address"]
                    port = outbound["settings"]["vnext"][0]["port"]
                    # method = ","
                elif protocol == "shadowsocks":
                    address = outbound["settings"]["servers"][0]["address"]
                    port = outbound["settings"]["servers"][0]["port"]
                    method = outbound["settings"]["servers"][0]["method"]
                else:
                    address = outbound["settings"]["servers"][0]["address"]
                    port = outbound["settings"]["servers"][0]["port"]
                    print("-----------理论上是不能到这里的-------------------")

                task = asyncio.ensure_future(check_proxy(
                    tag, proxy_host, proxy_port, protocol, address, port, method))
                tasks.append(task)
    await asyncio.gather(*tasks)


def check_ip_duplicates(input_file, ok_filename, nook_filename):
    # 定义两个集合用于检查 IP 是否重复
    ip_set = set()
    duplicate_ip_set = set()

    # 读取 input_file 文件
    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # 遍历所有行
    for line in lines:
        # 解析 IP 地址
        ip = line.split('当前 IP：')[1].split()[0]

        if ip not in ip_set:
            # 如果 IP 不重复，将整行写入 ok.txt 文件
            with open(ok_filename, 'a', encoding='utf-8') as ok_file:
                ok_file.write(line)

            # 将 IP 添加到集合中
            ip_set.add(ip)
        else:
            # 如果 IP 重复，将整行写入 nook.txt 文件
            with open(nook_filename, 'a', encoding='utf-8') as nook_file:
                nook_file.write(line)

            # 将 IP 添加到重复 IP 的集合中
            duplicate_ip_set.add(ip)

    # 输出结果
    print(f'共找到 {len(ip_set)} 条不重复的记录，已写入到 {ok_filename} 文件')
    print(f'发现 {len(duplicate_ip_set)} 个重复的 IP，对应的行已写入到 {nook_filename} 文件')


def main():
    # 清空文件内容
    with open('result.txt', 'w', encoding='utf-8') as f:
        f.write('')
        print("清空result.txt")
    with open('ok.txt', 'w', encoding='utf-8') as f:
        f.write('')
        print("清空ok.txt")
    with open('nook.txt', 'w', encoding='utf-8') as f:
        f.write('')
        print("清空ok.txt")

    # 订阅链接
    subscribe_url = "https://xxxxx.xyz/api/v1/client/subscribe?token=xxxxxxxxxxxxxxxxxxxx"
    node_list = parse_subscribe_url(subscribe_url)
    print("订阅成功...")
    v2ray_path = os.path.join(os.getcwd(), "Xray")
    config = generate_config_json(node_list, v2ray_path)
    print("生成config.json成功...")
    # # 启动子进程
    cmd = [os.path.join(v2ray_path, "xray.exe"), '-config',
           os.path.join(v2ray_path, "config.json")]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("启动xray成功...")
    print("等待10秒")
    time.sleep(10)
    # 代理检测
    loop = asyncio.get_event_loop()
    loop.run_until_complete(check_proxy_list(
        config['inbounds'], config['outbounds']))
    # write_distinct_ips_to_file()
    check_ip_duplicates('result.txt', 'ok.txt', 'nook.txt')


if __name__ == "__main__":
    main()
