# Import cụ thể từ Scapy để tránh lỗi Pylance
from scapy.all import (
    Ether, IP, ARP, ICMP, TCP, UDP, Raw,
    sr1, sr, send, sniff, get_if_list, get_if_addr, get_if_hwaddr,
    RandShort
)
try:
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
import threading
import time
import platform
import socket
import binascii

# --- Cấu hình ---
# Interface mặc định (sẽ được cập nhật động)
INTERFACE = None

# Biến toàn cục để quản lý trạng thái và dữ liệu
captured_packets = []
is_sniffing = False
sniff_thread = None
sniff_lock = threading.Lock()

# --- 1. Hàm liệt kê Network Interfaces ---

def get_network_interfaces():
    """Lấy danh sách tất cả network interfaces có sẵn."""
    interfaces = []
    try:
        if platform.system() == "Windows":
            # Trên Windows, get_if_list() trả về tên interface
            if_list = get_if_list()
            for iface in if_list:
                try:
                    # Lấy thông tin chi tiết về interface
                    addr = get_if_addr(iface)
                    hwaddr = get_if_hwaddr(iface)
                    interfaces.append({
                        "name": iface,
                        "ip": addr if addr != "0.0.0.0" else "No IP",
                        "mac": hwaddr if hwaddr else "N/A",
                        "status": "Active" if addr != "0.0.0.0" else "Inactive"
                    })
                except Exception:
                    # Bỏ qua interface không thể truy cập
                    continue
        else:
            # Trên Linux/Mac
            if_list = get_if_list()
            for iface in if_list:
                try:
                    addr = get_if_addr(iface)
                    hwaddr = get_if_hwaddr(iface)
                    interfaces.append({
                        "name": iface,
                        "ip": addr if addr != "0.0.0.0" else "No IP",
                        "mac": hwaddr if hwaddr else "N/A",
                        "status": "Active" if addr != "0.0.0.0" else "Inactive"
                    })
                except Exception:
                    continue
    except Exception as e:
        print(f"Error getting interfaces: {e}")
    
    return interfaces

def set_interface(iface_name):
    """Thiết lập interface để sử dụng."""
    global INTERFACE
    try:
        # Kiểm tra interface có tồn tại không
        if iface_name in get_if_list():
            INTERFACE = iface_name
            return True, f"Interface set to {iface_name}"
        else:
            return False, f"Interface {iface_name} not found"
    except Exception as e:
        return False, f"Error setting interface: {e}"

def get_current_interface():
    """Lấy interface hiện tại."""
    global INTERFACE
    if INTERFACE is None:
        # Tự động chọn interface đầu tiên có IP
        interfaces = get_network_interfaces()
        for iface in interfaces:
            if iface["ip"] != "No IP":
                INTERFACE = iface["name"]
                break
        if INTERFACE is None and interfaces:
            INTERFACE = interfaces[0]["name"]
    return INTERFACE

def packet_callback(packet):
    """Hàm được gọi cho mỗi gói tin được bắt."""
    global captured_packets
    if is_sniffing:
        try:
            with sniff_lock:
                packet_info = parse_packet(packet)
                # Chuyển đổi sang format frontend
                frontend_format = packet_to_frontend_format(packet_info, packet)
                frontend_format["id"] = len(captured_packets) + 1
                frontend_format["direction"] = "sniffed"
                frontend_format["time"] = time.strftime("%H:%M:%S", time.localtime())
                captured_packets.append(frontend_format)
        except Exception as e:
            with sniff_lock:
                # Tạo format frontend lỗi
                error_packet = {
                    "id": len(captured_packets) + 1,
                    "ts": int(time.time() * 1000),
                    "time": time.strftime("%H:%M:%S", time.localtime()),
                    "direction": "error",
                    "obj": {
                        "ip": {"src": "N/A", "dst": "N/A"},
                        "ethernet": {"src": "N/A", "dst": "N/A"},
                        "transport": {"proto": "Error", "sport": "", "dport": "", "flags": ""},
                        "payload": f"Error parsing packet: {str(e)}"
                    },
                    "hex": "",
                    "error": str(e)
                }
                captured_packets.append(error_packet)

def parse_packet(packet):
    """Phân tích gói tin và trích xuất thông tin chi tiết."""
    # Kiểm tra packet có hợp lệ không
    if packet is None:
        return {
            "source": "N/A",
            "destination": "N/A",
            "protocol": "Unknown",
            "length": 0,
            "summary": "Invalid packet (None)",
            "layers": [],
            "details": "Packet is None"
        }
    
    try:
        packet_length = len(packet)
        packet_summary = packet.summary()
    except Exception as e:
        # Nếu không thể lấy length hoặc summary, packet có thể bị corrupt
        return {
            "source": "N/A",
            "destination": "N/A",
            "protocol": "Unknown",
            "length": 0,
            "summary": f"Corrupt packet: {str(e)}",
            "layers": [],
            "details": f"Error accessing packet: {str(e)}"
        }
    
    info = {
        "source": "N/A",
        "destination": "N/A",
        "protocol": "Unknown",
        "length": packet_length,
        "summary": packet_summary,
        "layers": [],
        "details": ""
    }
    
    # Lấy danh sách các layer
    layers = []
    try:
        p = packet
        while p:
            layer_name = p.__class__.__name__
            layers.append(layer_name)
            if p.payload == p or not hasattr(p, 'payload'):
                break
            p = p.payload
    except Exception as e:
        # Nếu không thể lấy layers, vẫn tiếp tục với layers rỗng
        pass
    
    info["layers"] = layers
    
    # Trích xuất thông tin từ các layer
    try:
        # Ethernet layer
        try:
            if Ether in packet:
                info["src_mac"] = packet[Ether].src
                info["dst_mac"] = packet[Ether].dst
                info["ethertype"] = packet[Ether].type
        except Exception as e:
            pass  # Bỏ qua nếu không parse được Ethernet
        
        # IP layer
        try:
            if IP in packet:
                info["source"] = packet[IP].src
                info["destination"] = packet[IP].dst
                info["ttl"] = packet[IP].ttl
                info["version"] = packet[IP].version
                info["protocol_num"] = packet[IP].proto
                info["ip_ihl"] = packet[IP].ihl  # Header length (in 32-bit words)
                info["ip_tos"] = packet[IP].tos  # Type of Service / DSCP
                info["ip_len"] = packet[IP].len  # Total length
                info["ip_id"] = packet[IP].id  # Identification
                # Chuyển FlagValue thành số nguyên để JSON serialize được
                ip_flags_raw = packet[IP].flags
                info["ip_flags"] = int(ip_flags_raw) if hasattr(ip_flags_raw, '__int__') else ip_flags_raw
                info["ip_frag"] = packet[IP].frag  # Fragment offset
                info["ip_chksum"] = packet[IP].chksum  # Header checksum
        except Exception as e:
            pass  # Bỏ qua nếu không parse được IP
        
        # ARP layer
        try:
            if ARP in packet:
                info["source"] = packet[ARP].psrc
                info["destination"] = packet[ARP].pdst
                info["protocol"] = "ARP"
                info["arp_op"] = packet[ARP].op  # 1 = who-has, 2 = is-at
                info["arp_hwsrc"] = packet[ARP].hwsrc
                info["arp_hwdst"] = packet[ARP].hwdst
        except Exception as e:
            pass  # Bỏ qua nếu không parse được ARP
        
        # Transport layers - Check TCP và UDP trước ICMP (vì TCP/UDP có thể có payload)
        # TCP layer
        try:
            if TCP in packet:
                info["protocol"] = "TCP"
                info["src_port"] = packet[TCP].sport
                info["dst_port"] = packet[TCP].dport
                # Chuyển FlagValue thành số nguyên để JSON serialize được
                tcp_flags_raw = packet[TCP].flags
                info["tcp_flags"] = int(tcp_flags_raw) if hasattr(tcp_flags_raw, '__int__') else tcp_flags_raw
                info["seq"] = packet[TCP].seq
                info["ack"] = packet[TCP].ack
                info["win"] = packet[TCP].window
                info["tcp_dataofs"] = packet[TCP].dataofs  # Data offset (header length)
                info["tcp_reserved"] = packet[TCP].reserved
                info["tcp_urgptr"] = packet[TCP].urgptr
                info["tcp_chksum"] = packet[TCP].chksum
                # TCP options
                if hasattr(packet[TCP], 'options') and packet[TCP].options:
                    for opt in packet[TCP].options:
                        if opt[0] == 'MSS':
                            info["tcp_mss"] = opt[1]
                        elif opt[0] == 'WScale':
                            info["tcp_wscale"] = opt[1]
                        elif opt[0] == 'SAckOK':
                            info["tcp_sack_perm"] = True
        except Exception as e:
            pass  # Bỏ qua nếu không parse được TCP
        
        # UDP layer
        try:
            if UDP in packet:
                info["protocol"] = "UDP"
                info["src_port"] = packet[UDP].sport
                info["dst_port"] = packet[UDP].dport
                info["udp_len"] = packet[UDP].len
                info["udp_chksum"] = packet[UDP].chksum
                # Kiểm tra DNS (port 53)
                if DNS_AVAILABLE and (packet[UDP].sport == 53 or packet[UDP].dport == 53):
                    try:
                        if DNS in packet:
                            info["protocol"] = "DNS"
                            info["dns_qr"] = packet[DNS].qr  # 0 = query, 1 = response
                            info["dns_opcode"] = packet[DNS].opcode
                            info["dns_rcode"] = packet[DNS].rcode
                            if DNSQR in packet:
                                try:
                                    info["dns_qname"] = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                                except:
                                    info["dns_qname"] = str(packet[DNSQR].qname)
                                info["dns_qtype"] = packet[DNSQR].qtype
                            if DNSRR in packet:
                                dns_rr = packet[DNSRR]
                                if hasattr(dns_rr, 'rdata'):
                                    info["dns_rdata"] = str(dns_rr.rdata)
                                if hasattr(dns_rr, 'rrname'):
                                    try:
                                        info["dns_rrname"] = dns_rr.rrname.decode('utf-8', errors='ignore').rstrip('.')
                                    except:
                                        info["dns_rrname"] = str(dns_rr.rrname)
                    except Exception as dns_err:
                        # Nếu parse DNS lỗi, giữ nguyên UDP
                        pass
        except Exception as e:
            pass  # Bỏ qua nếu không parse được UDP
        
        # ICMP layer (check sau TCP/UDP)
        try:
            if ICMP in packet:
                info["protocol"] = "ICMP"
                info["icmp_type"] = packet[ICMP].type
                info["icmp_code"] = packet[ICMP].code
        except Exception as e:
            pass  # Bỏ qua nếu không parse được ICMP
        
        # Raw payload - Lấy trực tiếp từ packet để có thể decode HTTP
        try:
            if Raw in packet:
                payload = packet[Raw].load
                info["payload"] = payload.hex() if isinstance(payload, bytes) else str(payload)
                info["payload_length"] = len(payload)
                # Lưu thêm payload bytes để decode sau
                if isinstance(payload, bytes):
                    info["payload_bytes"] = payload
        except Exception as e:
            pass  # Bỏ qua nếu không parse được Raw
        
        # Lấy protocol name từ layer cuối cùng
        try:
            if not info["protocol"] or info["protocol"] == "Unknown":
                last_layer = packet.lastlayer()
                if last_layer:
                    info["protocol"] = last_layer.name if hasattr(last_layer, 'name') else last_layer.__class__.__name__
        except Exception as e:
            pass  # Bỏ qua nếu không lấy được protocol name
        
        # Chi tiết đầy đủ
        try:
            info["details"] = packet.show(dump=True)
        except Exception as e:
            info["details"] = f"Error getting details: {str(e)}"
        
    except Exception as e:
        info["details"] = f"Error parsing: {str(e)}"
    
    return info

def packet_to_frontend_format(packet_info, packet=None):
    """Chuyển đổi packet info từ format backend sang format frontend."""
    # Tạo hex dump từ packet nếu có
    hex_str = ""
    if packet is not None:
        try:
            hex_str = binascii.hexlify(bytes(packet)).decode('utf-8')
            # Format hex với khoảng trắng mỗi 2 ký tự
            hex_str = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
        except:
            hex_str = ""
    
    # Lấy payload dạng string
    payload_str = ""
    if "payload_bytes" in packet_info:
        # Ưu tiên dùng payload_bytes nếu có (từ Raw layer)
        try:
            payload_str = packet_info["payload_bytes"].decode('utf-8', errors='ignore')
        except:
            payload_str = ""
    elif "payload" in packet_info:
        payload_hex = packet_info["payload"]
        try:
            # Nếu là hex string, chuyển sang text
            if isinstance(payload_hex, str) and len(payload_hex) > 0:
                try:
                    payload_bytes = bytes.fromhex(payload_hex.replace(' ', ''))
                    payload_str = payload_bytes.decode('utf-8', errors='ignore')
                except:
                    payload_str = payload_hex
        except:
            payload_str = str(packet_info.get("payload", ""))
    
    # Xác định protocol
    proto = packet_info.get("protocol", "Unknown")
    if proto == "ARP":
        # ARP không có transport layer
        flags = ""
    elif proto == "ICMP":
        # ICMP không có port, dùng type/code làm flags
        flags = f"type={packet_info.get('icmp_type', 0)} code={packet_info.get('icmp_code', 0)}"
    elif proto == "TCP":
        # TCP flags từ Scapy là số (bitmask), convert sang text để hiển thị
        tcp_flags_num = packet_info.get("tcp_flags", 0)
        flags = convert_tcp_flags_num_to_text(tcp_flags_num)
    elif proto == "UDP":
        flags = ""
    elif proto == "DNS":
        dns_qr = packet_info.get("dns_qr", 0)
        if dns_qr == 0:
            flags = "Query"
            dns_qname = packet_info.get("dns_qname", "")
            if dns_qname:
                flags = f"Query: {dns_qname}"
        else:
            flags = "Response"
            dns_rrname = packet_info.get("dns_rrname", "")
            dns_rdata = packet_info.get("dns_rdata", "")
            if dns_rrname and dns_rdata:
                flags = f"Response: {dns_rrname} -> {dns_rdata}"
            elif dns_rrname:
                flags = f"Response: {dns_rrname}"
    else:
        flags = ""
    
    # Tạo object theo format frontend
    ip_obj = {
        "src": packet_info.get("source", "N/A"),
        "dst": packet_info.get("destination", "N/A")
    }
    # Thêm các IP fields nếu có (bỏ qua None)
    if packet_info.get("ttl") is not None:
        ip_obj["ttl"] = packet_info.get("ttl")
    if packet_info.get("version") is not None:
        ip_obj["version"] = packet_info.get("version")
    if packet_info.get("ip_ihl") is not None:
        ip_obj["ihl"] = packet_info.get("ip_ihl")
    if packet_info.get("ip_tos") is not None:
        ip_obj["tos"] = packet_info.get("ip_tos")
    if packet_info.get("ip_len") is not None:
        ip_obj["len"] = packet_info.get("ip_len")
    if packet_info.get("ip_id") is not None:
        ip_obj["id"] = packet_info.get("ip_id")
    if packet_info.get("ip_flags") is not None:
        ip_obj["flags"] = packet_info.get("ip_flags")
    if packet_info.get("ip_frag") is not None:
        ip_obj["frag"] = packet_info.get("ip_frag")
    if packet_info.get("ip_chksum") is not None:
        ip_obj["chksum"] = packet_info.get("ip_chksum")
    if packet_info.get("protocol_num") is not None:
        ip_obj["proto"] = packet_info.get("protocol_num")
    
    frontend_obj = {
        "ip": ip_obj,
        "ethernet": {
            "src": packet_info.get("src_mac", "N/A"),
            "dst": packet_info.get("dst_mac", "N/A"),
            "type": packet_info.get("ethertype")
        },
        "transport": {
            "proto": proto,
            "sport": str(packet_info.get("src_port", "")),
            "dport": str(packet_info.get("dst_port", "")),
            "flags": flags
        },
        "arp": {
            "op": packet_info.get("arp_op"),
            "hwsrc": packet_info.get("arp_hwsrc"),
            "hwdst": packet_info.get("arp_hwdst")
        },
        "payload": payload_str
    }
    
    # Thêm icmp_type và icmp_code vào transport object nếu là ICMP
    if proto == "ICMP":
        frontend_obj["transport"]["icmp_type"] = packet_info.get('icmp_type')
        frontend_obj["transport"]["icmp_code"] = packet_info.get('icmp_code')
    
    # Lấy packet length từ packet_info hoặc tính từ packet
    packet_length = packet_info.get("length", 0)
    if packet_length == 0 and packet is not None:
        try:
            packet_length = len(packet)
        except:
            packet_length = 0
    
    return {
        "ts": int(time.time() * 1000),  # milliseconds
        "obj": frontend_obj,
        "hex": hex_str,
        "length": packet_length  # Thêm length vào frontend format
    }

def sniff_target(filter_str="", interface=None):
    """Hàm chạy trong thread để thực hiện bắt gói tin."""
    global is_sniffing
    iface = interface or get_current_interface()
    
    # Trên Windows, sniffing không chỉ định interface thường bắt được nhiều packet hơn
    # (bao gồm cả packet từ terminal như ping)
    use_interface = iface
    if platform.system() == "Windows":
        # Thử sniffing không chỉ định interface để bắt được tất cả traffic
        use_interface = None
        print(f"Sniffing started (Windows - all interfaces) with filter: {filter_str}")
    else:
        print(f"Sniffing started on {iface} with filter: {filter_str}")
    
    try:
        while is_sniffing:
            try:
                sniff(
                    iface=use_interface,
                    filter=filter_str if filter_str else None,
                    prn=packet_callback,
                    store=0,
                    timeout=1,
                    stop_filter=lambda p: not is_sniffing
                )
            except Exception as sniff_err:
                # Nếu lỗi, thử với interface cụ thể (fallback)
                if use_interface is None and iface:
                    print(f"Warning: Sniffing without interface failed, trying with {iface}: {sniff_err}")
                    try:
                        sniff(
                            iface=iface,
                            filter=filter_str if filter_str else None,
                            prn=packet_callback,
                            store=0,
                            timeout=1,
                            stop_filter=lambda p: not is_sniffing
                        )
                        use_interface = iface  # Dùng interface cụ thể từ giờ
                    except Exception as e2:
                        print(f"Sniffing error (fallback): {e2}")
                        time.sleep(0.5)
                else:
                    print(f"Sniffing error: {sniff_err}")
                    time.sleep(0.5)
    except Exception as e:
        print(f"Sniffing error: {e}")
    finally:
        if is_sniffing:
            is_sniffing = False
        print("Sniffing thread stopped.")

def start_sniffing(filter_str="", interface=None):
    """API public để bắt đầu bắt gói tin."""
    global sniff_thread, is_sniffing, captured_packets
    
    if is_sniffing:
        return False, "Sniffing already in progress."
    
    iface = interface or get_current_interface()
    if not iface:
        return False, "No network interface available."
    
    captured_packets = []
    is_sniffing = True
    
    sniff_thread = threading.Thread(target=sniff_target, args=(filter_str, iface))
    sniff_thread.daemon = True
    sniff_thread.start()
    
    return True, f"Sniffing started on {iface}"

def stop_sniffing():
    """API public để dừng bắt gói tin."""
    global is_sniffing
    if is_sniffing:
        is_sniffing = False
        time.sleep(0.5)  # Đợi thread dừng
        return True, "Sniffing stopped."
    return False, "Sniffing was not running."

def get_captured_packets():
    """Trả về danh sách gói tin."""
    with sniff_lock:
        return captured_packets.copy()

def clear_captured_packets():
    """Xóa danh sách gói tin đã bắt."""
    global captured_packets
    with sniff_lock:
        captured_packets = []

def convert_tcp_flags_num_to_text(flags_num):
    """Convert TCP flags từ số (bitmask) sang text (SYN, ACK, etc.)"""
    # Chuyển FlagValue thành số nếu cần
    if hasattr(flags_num, '__int__'):
        flags_num = int(flags_num)
    if not flags_num or flags_num == 0:
        return ""
    
    # TCP flags bitmask:
    # FIN = 0x01 (1), SYN = 0x02 (2), RST = 0x04 (4), PSH = 0x08 (8)
    # ACK = 0x10 (16), URG = 0x20 (32), ECE = 0x40 (64), CWR = 0x80 (128)
    flag_names = []
    if flags_num & 0x01: flag_names.append("FIN")
    if flags_num & 0x02: flag_names.append("SYN")
    if flags_num & 0x04: flag_names.append("RST")
    if flags_num & 0x08: flag_names.append("PSH")
    if flags_num & 0x10: flag_names.append("ACK")
    if flags_num & 0x20: flag_names.append("URG")
    if flags_num & 0x40: flag_names.append("ECE")
    if flags_num & 0x80: flag_names.append("CWR")
    
    if not flag_names:
        return str(flags_num)  # Fallback: trả về số nếu không match
    
    return "-".join(flag_names)  # Ví dụ: "SYN-ACK"

# PHẦN 2 - COMMENTED OUT
# def convert_tcp_flags(flags_input):
#     """Convert TCP flags từ text (SYN, ACK, FIN, etc.) sang ký tự Scapy (S, A, F, etc.)"""
#     if not flags_input:
#         return "S"  # Default SYN
#     
#     flags_str = str(flags_input).strip().upper()
#     
#     # Nếu đã là ký tự Scapy hợp lệ (S, A, F, R, P, U), giữ nguyên
#     valid_scapy_flags = set("SAFRPU")
#     if all(c in valid_scapy_flags for c in flags_str):
#         return flags_str
#     
#     # Mapping từ text sang ký tự Scapy
#     flag_map = {
#         "SYN": "S",
#         "ACK": "A",
#         "FIN": "F",
#         "RST": "R",
#         "PSH": "P",
#         "PUSH": "P",
#         "URG": "U",
#         "SYN-ACK": "SA",
#         "SYNACK": "SA",
#         "FIN-ACK": "FA",
#         "FINACK": "FA"
#     }
#     
#     # Thử tìm exact match
#     if flags_str in flag_map:
#         return flag_map[flags_str]
#     
#     # Thử parse từng từ (ví dụ: "SYN ACK" -> "SA")
#     result = ""
#     words = flags_str.replace("-", " ").replace(",", " ").split()
#     for word in words:
#         if word in flag_map:
#             result += flag_map[word]
#         elif word in valid_scapy_flags:
#             result += word
#     
#     # Nếu không parse được gì, trả về default
#     return result if result else "S"

# PHẦN 2 - COMMENTED OUT
# def build_packet(packet_config, interface=None):
#     """
#     Xây dựng gói tin từ cấu hình.
    
#     packet_config format:
#     {
#         "ethernet": {"src": "...", "dst": "..."},
#         "ip": {"src": "...", "dst": "...", "ttl": 64},
#         "protocol": "ICMP|TCP|UDP",
#         "icmp": {"type": 8, "code": 0},
#         "tcp": {"sport": 12345, "dport": 80, "flags": "S"},
#         "udp": {"sport": 12345, "dport": 53},
#         "payload": "..."
#     }
#     """
#     try:
#         packet = None
#         if not interface or (isinstance(interface, str) and interface.strip() == ""):
#             iface = get_current_interface()
#         else:
#             iface = interface
        
#         if not iface:
#             iface = get_current_interface()
        
#         ip_config = packet_config.get("ip", {})
#         dst_ip = ip_config.get("dst")
#         if not dst_ip:
#             return False, "Destination IP is required"
        
#         dst_ip_str = str(dst_ip).strip()
        
#         if dst_ip_str.isdigit() or (dst_ip_str.replace(".", "").isdigit() and "." not in dst_ip_str):
#             return False, f"Invalid IP address format: '{dst_ip}'. Please use valid IPv4 format (e.g., 8.8.8.8) or hostname."
        
#         try:
#             socket.inet_pton(socket.AF_INET, dst_ip_str)
#         except (socket.error, OSError, ValueError):
#             try:
#                 socket.inet_pton(socket.AF_INET6, dst_ip_str)
#             except (socket.error, OSError, ValueError):
#                 if dst_ip_str.lower() == "localhost":
#                     pass
#                 elif "." not in dst_ip_str and ":" not in dst_ip_str:
#                     return False, f"Invalid IP address format: '{dst_ip}'. Please use valid IPv4 (e.g., 8.8.8.8), IPv6, or hostname."
        
#         dst_ip = dst_ip_str
        
#         use_ethernet = False
#         packet = None
        
#         if packet_config.get("ethernet"):
#             eth_config = packet_config["ethernet"]
#             src_mac = eth_config.get("src")
#             dst_mac = eth_config.get("dst", "ff:ff:ff:ff:ff:ff")
            
#             if src_mac and src_mac.strip():
#                 use_ethernet = True
#                 packet = Ether(src=src_mac, dst=dst_mac)
#             elif dst_ip in ["127.0.0.1", "localhost"]:
#                 use_ethernet = False
#             elif isinstance(dst_ip, str):
#                 is_lan = False
#                 try:
#                     if dst_ip.startswith("192.168.") or dst_ip.startswith("10."):
#                         is_lan = True
#                     elif dst_ip.startswith("172."):
#                         parts = dst_ip.split(".")
#                         if len(parts) > 1 and parts[1].isdigit():
#                             second_octet = int(parts[1])
#                             if 16 <= second_octet <= 31:
#                                 is_lan = True
#                 except (ValueError, IndexError):
#                     is_lan = False
                
#                 if is_lan:
#                     use_ethernet = False
        
#         src_ip = ip_config.get("src")
#         if not src_ip or (isinstance(src_ip, str) and src_ip.strip() == ""):
#             src_ip = None
#             if iface:
#                 try:
#                     test_ip = get_if_addr(iface)
#                     if test_ip and test_ip != "0.0.0.0":
#                         src_ip = test_ip
#                 except:
#                     pass
            
#             if not src_ip:
#                 interfaces = get_network_interfaces()
#                 for iface_info in interfaces:
#                     if iface_info["ip"] != "No IP" and iface_info["ip"] != "0.0.0.0":
#                         try:
#                             test_ip = get_if_addr(iface_info["name"])
#                             if test_ip and test_ip != "0.0.0.0":
#                                 src_ip = test_ip
#                                 iface = iface_info["name"]
#                                 break
#                         except:
#                             continue
            
#             if not src_ip:
#                 return False, "Cannot determine source IP. Please specify a source IP or ensure your network interface has an IP address."
        
#         if dst_ip in ["127.0.0.1", "localhost"]:
#             if src_ip not in ["127.0.0.1", "localhost", ""]:
#                 print(f"WARNING: Destination is localhost but source is {src_ip}. Setting source to 127.0.0.1 for proper routing.")
#                 src_ip = "127.0.0.1"
        
#         ip_layer = IP(
#             dst=dst_ip,
#             src=src_ip,
#             ttl=ip_config.get("ttl", 64),
#             tos=ip_config.get("tos", 0)
#         )
        
#         if use_ethernet and packet:
#             packet = packet / ip_layer
#         else:
#             packet = ip_layer
        
#         protocol = packet_config.get("protocol", "ICMP").upper()
        
#         if protocol == "ICMP":
#             icmp_config = packet_config.get("icmp", {})
#             icmp_type = icmp_config.get("type", 8)
#             icmp_code = icmp_config.get("code", 0)
#             packet = packet / ICMP(type=icmp_type, code=icmp_code)
            
#             payload = packet_config.get("payload", "")
#             if payload and payload.strip():
#                 if isinstance(payload, str):
#                     payload = payload.encode('utf-8')
#                 packet = packet / Raw(load=payload)
        
#         elif protocol == "TCP":
#             tcp_config = packet_config.get("tcp", {})
#             sport_raw = tcp_config.get("sport")
#             if sport_raw is None or sport_raw == "" or sport_raw == 0:
#                 sport = RandShort()
#             else:
#                 try:
#                     sport = int(sport_raw)
#                 except (ValueError, TypeError):
#                     sport = RandShort()
            
#             dport_raw = tcp_config.get("dport")
#             if dport_raw is None or dport_raw == "":
#                 dport = 80
#             else:
#                 try:
#                     dport = int(dport_raw)
#                 except (ValueError, TypeError):
#                     dport = 80
            
#             flags_raw = tcp_config.get("flags", "S")
#             payload = packet_config.get("payload", "")
#             if payload and payload.strip() and flags_raw.upper() in ["S", "SYN"]:
#                 print("WARNING: TCP packet has payload but flags is SYN. Changing to PSH+ACK.")
#                 flags_raw = "PA"
            
#             flags = convert_tcp_flags(flags_raw)
#             seq = tcp_config.get("seq", 0)
#             ack = tcp_config.get("ack", 0)
            
#             tcp_layer = TCP(
#                 sport=sport,
#                 dport=dport,
#                 flags=flags,
#                 seq=seq,
#                 ack=ack
#             )
#             packet = packet / tcp_layer
            
#             payload = packet_config.get("payload", "")
#             if payload and payload.strip():
#                 if isinstance(payload, str):
#                     payload = payload.encode('utf-8')
#                 packet = packet / Raw(load=payload)
        
#         elif protocol == "UDP":
#             udp_config = packet_config.get("udp", {})
#             sport_raw = udp_config.get("sport")
#             if sport_raw is None or sport_raw == "" or sport_raw == 0:
#                 sport = RandShort()
#             else:
#                 try:
#                     sport = int(sport_raw)
#                 except (ValueError, TypeError):
#                     sport = RandShort()
            
#             dport_raw = udp_config.get("dport")
#             if dport_raw is None or dport_raw == "":
#                 dport = 53
#             else:
#                 try:
#                     dport = int(dport_raw)
#                 except (ValueError, TypeError):
#                     dport = 53
            
#             udp_layer = UDP(sport=sport, dport=dport)
#             packet = packet / udp_layer
            
#             payload = packet_config.get("payload", "")
#             if payload and payload.strip():
#                 if isinstance(payload, str):
#                     payload = payload.encode('utf-8')
#                 packet = packet / Raw(load=payload)
        
#         else:
#             return False, f"Unsupported protocol: {protocol}"
        
#         return True, packet
        
#     except Exception as e:
#         return False, f"Error building packet: {str(e)}"

# PHẦN 2 - COMMENTED OUT
# def send_custom_packet(packet_config, interface=None, count=1, interval=0):
#     """
#     Gửi gói tin tùy chỉnh và tự động lưu gói tin đã gửi + phản hồi vào captured_packets.
#     """
#     global captured_packets
#     try:
#         iface = interface or get_current_interface()
#         if not iface:
#             return False, "No network interface available"
        
#         success, packet = build_packet(packet_config, iface)
#         if not success:
#             return False, packet
        
#         results = []
#         responses = []
        
#         for i in range(count):
#             try:
#                 print(f"Sending packet {i+1}/{count}: {packet.summary()}")
                
#                 sent_info = parse_packet(packet)
#                 sent_frontend = packet_to_frontend_format(sent_info, packet)
#                 with sniff_lock:
#                     sent_frontend["id"] = len(captured_packets) + 1
#                     sent_frontend["direction"] = "sent"
#                     captured_packets.append(sent_frontend)
                
#                 dst_ip = None
#                 src_ip = None
#                 if IP in packet:
#                     dst_ip = packet[IP].dst
#                     src_ip = packet[IP].src
#                     print(f"Sending to {dst_ip} from {src_ip}, waiting for response...")
                
#                 protocol_type = None
#                 if TCP in packet:
#                     protocol_type = "TCP"
#                 elif UDP in packet:
#                     protocol_type = "UDP"
#                 elif ICMP in packet:
#                     protocol_type = "ICMP"
                
#                 timeout = 5
#                 is_localhost = (dst_ip == "127.0.0.1" or 
#                                dst_ip == "localhost" or 
#                                str(dst_ip).strip() == "127.0.0.1" or
#                                str(dst_ip).strip() == "localhost")
                
#                 if is_localhost:
#                     if protocol_type == "ICMP":
#                         timeout = 3
#                     elif protocol_type == "TCP":
#                         timeout = 5
#                     else:
#                         timeout = 4
#                 elif protocol_type == "ICMP":
#                     timeout = 6
#                 else:
#                     timeout = 5
                
#                 response = None
#                 try:
#                     if is_localhost:
#                         ans, unans = sr(packet, timeout=timeout, verbose=0, retry=0)
#                         if ans:
#                             response = ans[0][1]
#                         else:
#                             response = None
#                     else:
#                         try:
#                             ans, unans = sr(packet, timeout=timeout, verbose=0, retry=0)
#                             if ans:
#                                 response = ans[0][1]
#                             else:
#                                 response = sr1(packet, timeout=timeout, verbose=0)
#                         except Exception as sr_err:
#                             response = sr1(packet, timeout=timeout, verbose=0)
#                     if response is not None:
#                         print(f"Response received: {response.summary()}")
#                         if IP in response:
#                             print(f"Response: src={response[IP].src}, dst={response[IP].dst}")
#                             if TCP in response:
#                                 flags = response[TCP].flags
#                                 if flags & 0x12:
#                                     print("Received SYN-ACK (connection accepted)")
#                                 elif flags & 0x04:
#                                     print("Received RST (connection refused/reset)")
#                             elif ICMP in response:
#                                 if response[ICMP].type == 0:
#                                     print("Received ICMP Echo Reply")
#                                 elif response[ICMP].type == 3:
#                                     print("Received ICMP Destination Unreachable")
#                     else:
#                         if protocol_type == "ICMP":
#                             print(f"No response received (timeout {timeout}s). Possible reasons:")
#                             print("  - Windows Firewall may be blocking ICMP")
#                             print("  - Need Administrator privileges for raw sockets")
#                             print("  - Some servers block ICMP echo requests")
#                         else:
#                             print(f"No response received (timeout {timeout}s). Possible reasons:")
#                             print("  - Port is closed or filtered by firewall")
#                             print("  - No service listening on destination port")
#                             print("  - Network unreachable")
#                 except Exception as e:
#                     print(f"Error in sr1(): {e}")
#                     response = None
                
#                 if response is None and is_localhost:
#                     print("Trying sniffing method for localhost...")
#                     try:
#                         protocol_type = None
#                         expected_sport = None
#                         expected_dport = None
                        
#                         if TCP in packet:
#                             protocol_type = "TCP"
#                             expected_sport = packet[TCP].dport
#                             expected_dport = packet[TCP].sport
#                         elif UDP in packet:
#                             protocol_type = "UDP"
#                             expected_sport = packet[UDP].dport
#                             expected_dport = packet[UDP].sport
#                         elif ICMP in packet:
#                             protocol_type = "ICMP"
                        
#                         captured_pkts = []
#                         stop_sniff = threading.Event()
                        
#                         def sniff_callback(pkt):
#                             if not stop_sniff.is_set() and IP in pkt:
#                                 if protocol_type == "ICMP" and ICMP in pkt:
#                                     if pkt[ICMP].type == 0:
#                                         captured_pkts.append(pkt)
#                                         stop_sniff.set()
#                                 elif protocol_type == "TCP" and TCP in pkt:
#                                     if pkt[TCP].sport == expected_sport and pkt[TCP].dport == expected_dport:
#                                         captured_pkts.append(pkt)
#                                         stop_sniff.set()
#                                 elif protocol_type == "UDP" and UDP in pkt:
#                                     if pkt[UDP].sport == expected_sport and pkt[UDP].dport == expected_dport:
#                                         captured_pkts.append(pkt)
#                                         stop_sniff.set()
                        
#                         def sniff_target_localhost():
#                             try:
#                                 if protocol_type == "ICMP":
#                                     filter_str = "icmp and host 127.0.0.1"
#                                 elif protocol_type == "TCP":
#                                     filter_str = f"tcp and host 127.0.0.1"
#                                 elif protocol_type == "UDP":
#                                     filter_str = f"udp and host 127.0.0.1"
#                                 else:
#                                     filter_str = "host 127.0.0.1"
                                
#                                 loopback_iface = None
#                                 try:
#                                     if_list = get_if_list()
#                                     for if_name in if_list:
#                                         if "loopback" in if_name.lower() or "npf_loopback" in if_name.lower():
#                                             loopback_iface = if_name
#                                             break
#                                 except Exception:
#                                     pass
                                
#                                 sniff_success = False
#                                 if loopback_iface:
#                                     try:
#                                         sniff(iface=loopback_iface, filter=filter_str, prn=sniff_callback,
#                                               stop_filter=lambda p: stop_sniff.is_set(), timeout=5, count=20, store=0)
#                                         sniff_success = True
#                                     except Exception:
#                                         pass
                                
#                                 if not sniff_success:
#                                     try:
#                                         sniff(filter=filter_str, prn=sniff_callback,
#                                               stop_filter=lambda p: stop_sniff.is_set(), timeout=5, count=20, store=0)
#                                         sniff_success = True
#                                     except Exception:
#                                         pass
                                
#                                 if not sniff_success:
#                                     try:
#                                         sniff(prn=sniff_callback, stop_filter=lambda p: stop_sniff.is_set(),
#                                               timeout=5, count=50, store=0)
#                                         sniff_success = True
#                                     except Exception:
#                                         pass
#                             except Exception as e:
#                                 print(f"Sniff error in thread: {e}")
#                                 import traceback
#                                 traceback.print_exc()
                        
#                         sniff_thread_localhost = threading.Thread(target=sniff_target_localhost)
#                         sniff_thread_localhost.daemon = True
#                         sniff_thread_localhost.start()
                        
#                         time.sleep(0.5)
#                         send(packet, verbose=0)
#                         sniff_thread_localhost.join(timeout=6)
#                         stop_sniff.set()
                        
#                         if captured_pkts:
#                             response = captured_pkts[0]
#                         else:
#                             print("No response via sniffing either")
#                     except Exception as sniff_err:
#                         print(f"Sniffing fallback failed: {sniff_err}")
                
#                 if response is not None:
#                     response_info = parse_packet(response)
#                     response_frontend = packet_to_frontend_format(response_info, response)
#                     with sniff_lock:
#                         response_frontend["id"] = len(captured_packets) + 1
#                         response_frontend["direction"] = "received"
#                         captured_packets.append(response_frontend)
                    
#                     responses.append(response_frontend)
#                     results.append(f"Packet {i+1}: Response received - {response.summary()}")
#                 else:
#                     results.append(f"Packet {i+1}: Sent, no response received")
                
#                 if i < count - 1 and interval > 0:
#                     time.sleep(interval)
                    
#             except Exception as e:
#                 results.append(f"Packet {i+1}: Error - {str(e)}")
        
#         return True, {
#             "message": f"Sent {count} packet(s)",
#             "results": results,
#             "responses": responses,
#             "packet_summary": packet.summary()
#         }
        
#     except Exception as e:
#         return False, f"Error sending packet: {str(e)}"
