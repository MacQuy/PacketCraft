import socket
import time
from flask import Flask, jsonify, request
from scapy.all import (
    conf, get_if_list, sendp, sniff, sr1, Ether, IP, IPv6, ARP, ICMP, UDP, TCP, Raw
)
from scapy.layers.inet6 import (
    ICMPv6EchoRequest, ICMPv6EchoReply,
    ICMPv6ND_NS, ICMPv6ND_NA
)
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

def safe_int(val, default=None, base=10):
    if val is None or val == "":
        return default
    try:
        return int(val, 0)
    except Exception:
        try:
            return int(val)
        except Exception:
            return default


def clean_str(val):
    if val is None:
        return None
    s = str(val).strip()
    return s if s != "" else None

def packet_to_json(pkt):
    if pkt is None:
        return None

    result = {}

    if Ether in pkt:
        eth = pkt[Ether]
        result["eth"] = {
            "eth_src": eth.src,
            "eth_dst": eth.dst,
            "eth_type": hex(eth.type)
        }

    if IP in pkt:
        ip4 = pkt[IP]
        result["ip"] = {
            "ipv4_src": ip4.src,
            "ipv4_dst": ip4.dst,
            "ttl": ip4.ttl,
            "ip_id": ip4.id,
            "flags": str(ip4.flags)
        }

    if IPv6 in pkt:
        ip6 = pkt[IPv6]
        result["ipv6"] = {
            "ipv6_src": ip6.src,
            "ipv6_dst": ip6.dst
        }

    if ARP in pkt:
        arp = pkt[ARP]
        result["arp"] = {
            "hwsrc": arp.hwsrc,
            "hwdst": arp.hwdst,
            "psrc": arp.psrc,
            "pdst": arp.pdst,
            "op": arp.op
        }

    if ICMP in pkt:
        icmp = pkt[ICMP]
        result["icmp"] = {
            "type": icmp.type,
            "code": icmp.code
        }

    if UDP in pkt:
        udp = pkt[UDP]
        result["udp"] = {
            "sport": udp.sport,
            "dport": udp.dport
        }
        
    if TCP in pkt:
        tcp = pkt[TCP]
        result["tcp"] = {
            "sport": tcp.sport,
            "dport": tcp.dport,
            "flags": tcp.flags
        }
        
    if Raw in pkt:
        result["payload"] = pkt[Raw].load.decode(errors="ignore")

    return result


@app.route('/interfaces', methods=['GET'])
def get_interfaces_api():
    try:
        interfaces = get_if_list()
        return jsonify({"status": "success", "interfaces": interfaces}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/send', methods=['POST'])
def send_packet():
    try:
        data = request.json
        iface = data.get('interface')
        tpl = data.get('packet', {}) or {}

        if not iface:
            return jsonify({"status": "error", "message": "interface required"}), 400

        eth_cfg = tpl.get('eth', {}) or {}
        eth_src = clean_str(eth_cfg.get('eth_src')) or "00:00:00:00:00:00"
        eth_dst = clean_str(eth_cfg.get('eth_dst')) or "ff:ff:ff:ff:ff:ff"
        eth_type_raw = clean_str(eth_cfg.get('eth_type')) or "0x0800"
        eth_type = safe_int(eth_type_raw, 0x0800)

        eth = Ether(src=eth_src, dst=eth_dst, type=eth_type)
        packet = eth

        ip = None
        if 'ip' in tpl and tpl.get('ip'):
            ip_cfg = tpl['ip'] or {}
            ipv4_src = clean_str(ip_cfg.get('ipv4_src')) or '0.0.0.0'
            ipv4_dst = clean_str(ip_cfg.get('ipv4_dst')) or '0.0.0.0'
            ip_ttl = safe_int(ip_cfg.get('ip_ttl'), 64)
            ip_id = safe_int(ip_cfg.get('ip_id'), 1)
            ip_flags = clean_str(ip_cfg.get('flags'))

            ip_kwargs = dict(src=ipv4_src, dst=ipv4_dst, ttl=ip_ttl, id=ip_id)
            if ip_flags is not None:
                ip_kwargs['flags'] = ip_flags

            ip = IP(**ip_kwargs)
            packet /= ip

        ip6 = None
        if 'ipv6' in tpl and tpl.get('ipv6'):
            ip6_cfg = tpl['ipv6'] or {}
            ipv6_src = clean_str(ip6_cfg.get('ipv6_src')) or '::1'
            ipv6_dst = clean_str(ip6_cfg.get('ipv6_dst')) or '::1'
            ip6 = IPv6(src=ipv6_src, dst=ipv6_dst)
            packet /= ip6

        if 'arp' in tpl and tpl.get('arp'):
            arp_cfg = tpl['arp'] or {}
            op = safe_int(arp_cfg.get('op'), 1)
            psrc = clean_str(arp_cfg.get('ip_arp_src')) or '0.0.0.0'
            pdst = clean_str(arp_cfg.get('ip_arp_dst')) or '0.0.0.0'
            hwsrc = eth_src
            hwdst = eth_dst
            packet /= ARP(op=op, psrc=psrc, pdst=pdst, hwsrc=hwsrc, hwdst=hwdst)

        transport_cfg = tpl.get('transport') or {}
        proto = clean_str(transport_cfg.get('proto'))

        if proto:
            proto_l = proto.lower()
            if proto_l == 'icmp':
                if ip6 is not None:
                    ttype = safe_int(transport_cfg.get('type'), None)
                    if ttype == 128:
                        packet /= ICMPv6EchoRequest()
                    elif ttype == 129:
                        packet /= ICMPv6EchoReply()
                    elif ttype == 135:
                        packet /= ICMPv6ND_NS()
                    elif ttype == 136:
                        packet /= ICMPv6ND_NA()
                    else:
                        packet /= ICMPv6EchoRequest()
                else:
                    icmp_type = safe_int(transport_cfg.get('type'), 8)
                    icmp_code = safe_int(transport_cfg.get('code'), 0)
                    packet /= ICMP(type=icmp_type, code=icmp_code)

            elif proto_l == 'tcp':
                sport = safe_int(transport_cfg.get('sport'), 1234)
                dport = safe_int(transport_cfg.get('dport'), 80)
                seq = safe_int(transport_cfg.get('seq'), 0)
                ack = transport_cfg.get('ack')
                ack_val = safe_int(ack, None)
                flags = clean_str(transport_cfg.get('tcp_flags')) or ''

                tcp_kwargs = dict(sport=sport, dport=dport, seq=seq, flags=flags)
                if ack_val is not None:
                    tcp_kwargs['ack'] = ack_val

                packet /= TCP(**tcp_kwargs)

            elif proto_l == 'udp':
                sport = safe_int(transport_cfg.get('sport'), 5000)
                dport = safe_int(transport_cfg.get('dport'), 5000)
                packet /= UDP(sport=sport, dport=dport)

            else:
                pass

        payload = tpl.get('payload')
        if payload is not None and payload != "":
            if isinstance(payload, str):
                packet /= Raw(load=payload.encode('utf-8', errors='ignore'))
            else:
                packet /= Raw(load=payload)
                
        sendp(packet, iface=iface, verbose=False)

        resp = sniff_response(packet, iface, timeout=3)

        return jsonify({
            "status": "success",
            "sent_summary": packet_to_json(packet),
            "response_summary": packet_to_json(resp) if resp is not None else None
        }), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


def sniff_response(sent_packet, iface, timeout=3):
    ip = sent_packet.getlayer(IP)
    ip6 = sent_packet.getlayer(IPv6)
    tcp = sent_packet.getlayer(TCP)
    udp = sent_packet.getlayer(UDP)
    icmp = sent_packet.getlayer(ICMP)
    arp = sent_packet.getlayer(ARP)

    def flt(pkt):
        try:
            if arp:
                return pkt.haslayer(ARP) and pkt[ARP].op == 2 and pkt[ARP].psrc == arp.pdst

            if ip:
                if icmp:
                    return (pkt.haslayer(ICMP)
                            and pkt[IP].src == ip.dst
                            and pkt[IP].dst == ip.src
                            and pkt[ICMP].type in [0, 3, 11, 14])

                if tcp:
                    return (pkt.haslayer(TCP)
                            and pkt[IP].src == ip.dst
                            and pkt[IP].dst == ip.src
                            and pkt[TCP].sport == tcp.dport
                            and pkt[TCP].dport == tcp.sport)

                if udp:
                    if pkt.haslayer(UDP):
                        return (pkt[IP].src == ip.dst and pkt[IP].dst == ip.src
                                and pkt[UDP].sport == udp.dport and pkt[UDP].dport == udp.sport)
                    if pkt.haslayer(ICMP):
                        return (pkt[IP].src == ip.dst and pkt[ICMP].type in [3])

            if ip6:
                if tcp:
                    return pkt.haslayer(TCP) and pkt[IPv6].src == ip6.dst and pkt[IPv6].dst == ip6.src
                if udp:
                    return pkt.haslayer(UDP) and pkt[IPv6].src == ip6.dst and pkt[IPv6].dst == ip6.src
                if pkt.haslayer(ICMPv6EchoReply) or pkt.haslayer(ICMPv6ND_NA):
                    return pkt[IPv6].src == ip6.dst and pkt[IPv6].dst == ip6.src

            return False
        except Exception:
            return False

    pkts = sniff(iface=iface, timeout=timeout, lfilter=flt, count=1)
    return pkts[0] if pkts else None


def traceroute_host(host, max_hops=30, timeout=1, iface=None):
    target_ip = socket.gethostbyname(host)
    hops = []
    iface_to_use = iface or conf.iface

    for ttl in range(1, max_hops + 1):
        probe = IP(dst=target_ip, ttl=ttl) / ICMP()
        start_time = time.time()
        reply = sr1(probe, timeout=timeout, iface=iface_to_use, verbose=False)
        rtt_ms = round((time.time() - start_time) * 1000, 2)

        if reply is None:
            hops.append({
                "ttl": ttl,
                "ip": "*",
                "rtt_ms": None,
                "status": "timeout"
            })
            continue

        hop_ip = reply[IP].src if reply.haslayer(IP) else "*"
        status = "reply"

        if reply.haslayer(ICMP):
            icmp = reply.getlayer(ICMP)
            if icmp.type == 11:
                status = "ttl_exceeded"
            elif icmp.type == 0:
                status = "reached"
            elif icmp.type == 3:
                status = "unreachable"
            else:
                status = f"icmp_{icmp.type}"

        hops.append({
            "ttl": ttl,
            "ip": hop_ip,
            "rtt_ms": rtt_ms,
            "status": status
        })

        if hop_ip == target_ip or status == "reached":
            break

    return target_ip, hops


def parse_ports(port_spec):
    ports = set()
    if not port_spec:
        return []

    for chunk in str(port_spec).split(","):
        part = chunk.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start = safe_int(start_s, None)
            end = safe_int(end_s, None)
            if start is None or end is None:
                continue
            if start > end:
                start, end = end, start
            for p in range(start, end + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = safe_int(part, None)
            if p is not None and 1 <= p <= 65535:
                ports.add(p)

    return sorted(ports)


def scan_port(target_ip, port, timeout=1, iface=None):
    iface_to_use = iface or conf.iface
    syn = IP(dst=target_ip) / TCP(dport=port, flags="S")
    resp = sr1(syn, timeout=timeout, iface=iface_to_use, verbose=False)
    if resp is None:
        return "filtered"
    if resp.haslayer(TCP):
        flags = resp.getlayer(TCP).flags
        if flags == 0x12:
            sr1(IP(dst=target_ip) / TCP(dport=port, flags="R"), timeout=timeout, iface=iface_to_use, verbose=False)
            return "open"
        if flags == 0x14:
            return "closed"
    if resp.haslayer(ICMP):
        return "filtered"
    return "unknown"


@app.route('/traceroute', methods=['POST'])
def traceroute_api():
    try:
        data = request.json or {}
        host = clean_str(data.get("host"))
        if not host:
            return jsonify({"status": "error", "message": "host required"}), 400

        max_hops = safe_int(data.get("max_hops"), 30)
        timeout = safe_int(data.get("timeout"), 1)
        iface = clean_str(data.get("interface"))

        target_ip, hops = traceroute_host(host, max_hops=max_hops, timeout=timeout, iface=iface)

        return jsonify({
            "status": "success",
            "target": host,
            "target_ip": target_ip,
            "hops": hops
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/port-scan', methods=['POST'])
def port_scan_api():
    try:
        data = request.json or {}
        host = clean_str(data.get("host"))
        ports_spec = clean_str(data.get("ports"))
        if not host:
            return jsonify({"status": "error", "message": "host required"}), 400
        if not ports_spec:
            return jsonify({"status": "error", "message": "ports required"}), 400

        target_ip = socket.gethostbyname(host)
        ports = parse_ports(ports_spec)
        if not ports:
            return jsonify({"status": "error", "message": "no valid ports"}), 400

        timeout = safe_int(data.get("timeout"), 1)
        iface = clean_str(data.get("interface"))

        results = []
        for port in ports:
            state = scan_port(target_ip, port, timeout=timeout, iface=iface)
            results.append({"port": port, "state": state})

        return jsonify({
            "status": "success",
            "target": host,
            "target_ip": target_ip,
            "results": results
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
