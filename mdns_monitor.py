from scapy.all import sniff
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP
from flask import Flask, render_template, jsonify
import threading
import json

app = Flask(__name__)
mdns_records = []  # 使用列表保留所有记录


def packet_callback(packet):
    """处理捕获到的数据包"""
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

                mdns_records.append(record)
                print(f"New MDNS record: {name} ({ip})")


def start_sniffing():
    """开始嗅探MDNS数据包"""
    try:
        print("开始监听MDNS流量...")
        sniff(filter="udp port 5353", prn=packet_callback, store=0)
    except Exception as e:
        print(f"Error sniffing MDNS: {e}")


# Flask路由
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/mdns')
def get_mdns():
    # 按时间排序（最新的在前）
    sorted_records = sorted(mdns_records, key=lambda x: x['time'], reverse=True)
    return jsonify(sorted_records)


if __name__ == '__main__':
    # 启动MDNS捕获线程
    capture_thread = threading.Thread(target=start_sniffing, daemon=True)
    capture_thread.start()

    # 启动Flask应用
    app.run(debug=False,use_reloader=False, host='0.0.0.0', port=5000)