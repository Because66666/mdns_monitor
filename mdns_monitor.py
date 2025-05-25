import os
import platform
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP, IP
from scapy.sendrecv import sniff
from flask import Flask, render_template, jsonify
import threading
import json
import subprocess
import re
import time

app = Flask(__name__)
mdns_records = []  # 使用列表保留所有记录
wifi_records = []  # 存储WiFi信号记录
mdns_records_name_list = []

def packet_callback(packet):
    """处理捕获到的MDNS数据包"""
    global mdns_records

    if packet.haslayer(DNS) and (packet.haslayer(DNSQR) or packet.haslayer(DNSRR)):
        if packet.haslayer(UDP) and (packet[UDP].dport == 5353 or packet[UDP].sport == 5353):
            dns = packet[DNS]
            time = packet.time

            # 提取名称和IP地址
            name = ""
            ip = ""

            # 优先从响应中提取
            if dns.qr == 1 and dns.ancount > 0:
                for i in range(dns.ancount):
                    a = dns.an[i]
                    if a.type == 1:  # A记录 (IPv4)
                        name = a.rrname.decode('utf-8') if a.rrname else ""
                        ip = a.rdata
                        break
                    elif a.type == 28:  # AAAA记录 (IPv6)
                        name = a.rrname.decode('utf-8') if a.rrname else ""
                        ip = a.rdata
                        break

            # 如果响应中没有，尝试从查询中提取
            if not name and dns.qr == 0 and dns.qdcount > 0:
                q = dns.qd[0]
                name = q.qname.decode('utf-8') if q.qname else ""

            # 创建简化记录
            if name or ip:
                record = {
                    'time': time,
                    'name': name,
                    'ip': ip
                }
                if name not in mdns_records_name_list:
                    mdns_records_name_list.append(name)
                    mdns_records.append(record)
                else:
                    # 更新已有记录的时间戳
                    for existing_record in mdns_records:
                        if existing_record['name'] == name:
                            existing_record['time'] = time
                            break

                # print(f"New MDNS record: {name} ({ip})")


def scan_wifi():
    """扫描可用的WiFi信号"""
    global wifi_records
    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'
    try:
        # 使用不同操作系统的命令扫描WiFi
        if platform.system() == "Linux":
            # Linux系统
            cmd = ["iwlist", "scan"]
            # result = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
            result_bytes = subprocess.check_output(cmd, stderr=subprocess.STDOUT, env=env)
            result = result_bytes.decode('utf-8', errors='replace')
            # 解析WiFi名称
            wifi_names = re.findall(r'ESSID:"(.*?)"', result)

        elif platform.system() == "Windows":
            # Windows系统
            cmd = ["netsh", "wlan", "show", "networks"]
            # result = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode('gbk')
            result_bytes = subprocess.check_output(cmd, stderr=subprocess.STDOUT, env=env)
            result = result_bytes.decode('utf-8', errors='replace')
            # 解析WiFi名称
            wifi_names = re.findall(r'SSID\s+\d+\s+:\s(.*)', result)

        else:
            # 其他系统（如macOS）
            cmd = ["networksetup", "-listallhardwareports"]
            # result = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
            result_bytes = subprocess.check_output(cmd, stderr=subprocess.STDOUT, env=env)
            result = result_bytes.decode('utf-8', errors='replace')
            # 解析WiFi接口名称
            wifi_interface = re.search(r'Wi-Fi|AirPort\s+\n\s+Device:\s+(\w+)', result)
            if wifi_interface:
                interface = wifi_interface.group(1)
                cmd = ["airport",
                       f"/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
                       "-s"]
                result = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
                # 解析WiFi名称
                wifi_names = re.findall(r'^([^\t]+)', result, re.MULTILINE)
            else:
                wifi_names = []

        # 记录扫描时间
        scan_time = time.time()

        # 更新WiFi记录
        for name in wifi_names:
            flag = True # 是否是不存在于原本的记录里的
            for rec_wifi in wifi_records:
                rec_wifi_name = rec_wifi['name']
                if name == rec_wifi_name:
                    rec_wifi['time'] = scan_time
                    flag = False
                    break
            if flag:
                wifi_records.append({
                    'name':name,
                    'time':scan_time
                })

        # print(f"Scanned {len(wifi_records)} WiFi networks")

    except Exception as e:
        print(f"Error scanning WiFi: {e}")
        # 添加错误记录
        wifi_records = [{"name": "无法扫描WiFi", "time": time.time(), "error": True}]


def start_sniffing():
    """开始嗅探MDNS数据包"""
    try:
        print("开始监听MDNS流量...")
        sniff(filter="udp port 5353", prn=packet_callback, store=0)
    except Exception as e:
        print(f"Error sniffing MDNS: {e}")


def start_wifi_scan():
    """定期扫描WiFi"""
    try:
        print("开始WiFi扫描...")
        while True:
            scan_wifi()
            # 每30秒扫描一次
            time.sleep(30)
    except Exception as e:
        print(f"Error in WiFi scan thread: {e}")


# Flask路由
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/mdns')
def get_mdns():
    # 按时间排序（最新的在前）
    # 关键词列表
    keywords = ['ipad', 'macbook', 'iphone']

    # 定义排序函数
    def sort_key(record):
        name = record['name'].lower()
        # 检查是否包含关键词
        has_keyword = any(keyword in name for keyword in keywords)
        # 包含关键词的排前面，然后按时间排序
        return (-int(has_keyword), -record['time'])

    # 应用排序
    sorted_records = sorted(mdns_records, key=sort_key)
    return jsonify(sorted_records)


@app.route('/api/wifi')
def get_wifi():
    # 按时间排序（最新的在前）
    sorted_records = sorted(wifi_records, key=lambda x: -x['time'])
    return jsonify(sorted_records)


if __name__ == '__main__':
    # 启动MDNS捕获线程
    capture_thread = threading.Thread(target=start_sniffing, daemon=True)
    capture_thread.start()

    # 启动WiFi扫描线程
    wifi_thread = threading.Thread(target=start_wifi_scan, daemon=True)
    wifi_thread.start()

    # 启动Flask应用
    app.run(debug=True, host='0.0.0.0', port=5000)