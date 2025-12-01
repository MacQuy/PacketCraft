from flask import Flask, jsonify, request
from flask_cors import CORS
from scapy_utils import (
    # send_custom_packet,  # Phần 2 - Commented out
    # build_packet,  # Phần 2 - Commented out
    start_sniffing,
    stop_sniffing,
    get_captured_packets,
    clear_captured_packets,
    get_network_interfaces,
    set_interface,
    get_current_interface
)

app = Flask(__name__)
# Rất quan trọng: Cho phép frontend Electron gọi API từ các cổng khác nhau
CORS(app)

<<<<<<< HEAD
# --- API: Lấy danh sách Network Interfaces ---
@app.route('/api/interfaces', methods=['GET'])
def get_interfaces_api():
    """Lấy danh sách tất cả network interfaces."""
    try:
        interfaces = get_network_interfaces()
        current = get_current_interface()
        return jsonify({
            "status": "success",
            "interfaces": interfaces,
            "current": current
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# --- API: Thiết lập Network Interface ---
@app.route('/api/interfaces/set', methods=['POST'])
def set_interface_api():
    """Thiết lập interface để sử dụng."""
    try:
        data = request.json or {}
        iface_name = data.get('interface')
        
        if not iface_name:
            return jsonify({
                "status": "error",
                "message": "Interface name is required"
            }), 400
        
        success, message = set_interface(iface_name)
        
        if success:
            return jsonify({
                "status": "success",
                "message": message,
                "interface": iface_name
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": message
            }), 400
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# --- API: Bắt đầu Bắt gói tin ---
@app.route('/api/sniff/start', methods=['POST'])
def start_sniffing_api():
    """Bắt đầu bắt gói tin trên interface."""
    try:
        data = request.json or {}
        filter_str = data.get('filter', "")
        interface = data.get('interface')
        
        success, message = start_sniffing(filter_str=filter_str, interface=interface)
        
        if success:
            return jsonify({
                "status": "success",
                "message": message,
                "interface": get_current_interface()
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": message
            }), 400
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# --- API: Kiểm tra trạng thái sniffing ---
@app.route('/api/sniff/status', methods=['GET'])
def sniffing_status_api():
    """Kiểm tra trạng thái sniffing hiện tại."""
    try:
        from scapy_utils import is_sniffing
        return jsonify({
            "status": "success",
            "is_sniffing": is_sniffing,
            "message": "Sniffing is active" if is_sniffing else "Sniffing is not active"
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# --- API: Dừng Bắt gói tin ---
@app.route('/api/sniff/stop', methods=['POST'])
def stop_sniffing_api():
    """Dừng bắt gói tin."""
    try:
        success, message = stop_sniffing()
        if success:
            return jsonify({
                "status": "success",
                "message": message
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": message
            }), 400
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# --- API: Lấy danh sách gói tin đã bắt được ---
@app.route('/api/sniff/packets', methods=['GET'])
def get_packets_api():
    """
    Lấy danh sách gói tin đã bắt được (đã gửi, nhận, hoặc sniffed).
    Trả về format phù hợp với frontend.
    """
    try:
        packets = get_captured_packets()
        # Packets đã được lưu ở format frontend rồi
        # Đảm bảo tất cả giá trị có thể serialize JSON
        def convert_flagvalue(obj):
            """Recursively convert FlagValue objects to int"""
            if isinstance(obj, dict):
                return {k: convert_flagvalue(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_flagvalue(item) for item in obj]
            elif hasattr(obj, '__int__') and not isinstance(obj, (int, float, str, bool, type(None))):
                # FlagValue và các object tương tự có __int__ nhưng không phải số thông thường
                try:
                    return int(obj)
                except (ValueError, TypeError):
                    return str(obj)  # Fallback: convert to string
            else:
                return obj
        
        # Convert FlagValue objects in all packets
        packets = convert_flagvalue(packets)
        
        for pkt in packets:
            if "obj" in pkt and "ip" in pkt["obj"]:
                # Convert None values to None hoặc bỏ qua
                for key in ["ttl", "version", "ihl", "tos", "len", "id", "flags", "frag", "chksum", "proto"]:
                    if key in pkt["obj"]["ip"] and pkt["obj"]["ip"][key] is None:
                        del pkt["obj"]["ip"][key]
            if "obj" in pkt and "transport" in pkt["obj"]:
                # Convert None values
                for key in ["tcp_dataofs", "tcp_reserved", "tcp_urgptr", "tcp_chksum", "udp_len", "udp_chksum", "tcp_mss", "tcp_wscale"]:
                    if key in pkt["obj"]["transport"] and pkt["obj"]["transport"][key] is None:
                        del pkt["obj"]["transport"][key]
        return jsonify({
            "status": "success",
            "packets": packets,
            "count": len(packets)
        }), 200
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"Error in get_packets_api: {error_trace}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# --- API: Xóa danh sách gói tin đã bắt ---
@app.route('/api/sniff/clear', methods=['POST'])
def clear_packets_api():
    """Xóa danh sách gói tin đã bắt."""
    try:
        clear_captured_packets()
        return jsonify({
            "status": "success",
            "message": "Captured packets cleared"
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# --- API: Build Packet (Phần 2 - Build Packet) ---
# PHẦN 2 - COMMENTED OUT
# @app.route('/api/build', methods=['POST'])
# def build_packet_api():
#     """
#     Build packet từ cấu hình GUI (chưa gửi).
#     Trả về thông tin packet đã build để preview.
#     """
#     try:
#         data = request.json or {}
#         
#         if "ethernet" in data and "ip" in data and "transport" in data:
#             packet_config = {
#                 "ethernet": {
#                     "src": data["ethernet"].get("src") or "",
#                     "dst": data["ethernet"].get("dst") or "ff:ff:ff:ff:ff:ff",
#                     "type": data["ethernet"].get("type") or ""
#                 },
#                 "ip": {
#                     "src": data["ip"].get("src") or "",
#                     "dst": data["ip"].get("dst") or "",
#                     "ttl": int(data["ip"].get("ttl") or 64) if data["ip"].get("ttl") else 64
#                 },
#                 "protocol": data["transport"].get("proto", "ICMP").replace("v4", "").replace("v6", "").upper(),
#                 "payload": data.get("payload") or ""
#             }
#             
#             proto = packet_config["protocol"]
#             if proto == "ICMP":
#                 flags = data["transport"].get("flags", "")
#                 icmp_type = 8
#                 icmp_code = 0
#                 if "type=" in flags:
#                     try:
#                         icmp_type = int(flags.split("type=")[1].split()[0])
#                     except:
#                         pass
#                 if "code=" in flags:
#                     try:
#                         icmp_code = int(flags.split("code=")[1].split()[0])
#                     except:
#                         pass
#                 packet_config["icmp"] = {"type": icmp_type, "code": icmp_code}
#             elif proto == "TCP":
#                 sport_str = data["transport"].get("sport", "").strip()
#                 dport_str = data["transport"].get("dport", "").strip()
#                 tcp_config = {
#                     "dport": int(dport_str) if dport_str else 80,
#                     "flags": data["transport"].get("flags", "S")
#                 }
#                 if sport_str and sport_str != "0":
#                     try:
#                         tcp_config["sport"] = int(sport_str)
#                     except ValueError:
#                         pass
#                 packet_config["tcp"] = tcp_config
#             elif proto == "UDP":
#                 sport_str = data["transport"].get("sport", "").strip()
#                 dport_str = data["transport"].get("dport", "").strip()
#                 udp_config = {
#                     "dport": int(dport_str) if dport_str else 53
#                 }
#                 if sport_str and sport_str != "0":
#                     try:
#                         udp_config["sport"] = int(sport_str)
#                     except ValueError:
#                         pass
#                 packet_config["udp"] = udp_config
#             
#             interface = data.get("interface")
#             success, result = build_packet(packet_config, interface)
#             
#             if success:
#                 packet = result
#                 import binascii
#                 hex_str = ""
#                 try:
#                     hex_bytes = bytes(packet)
#                     hex_str = binascii.hexlify(hex_bytes).decode('utf-8')
#                     hex_str = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
#                 except Exception as e:
#                     hex_str = f"Error generating hex: {str(e)}"
#                 
#                 layers = []
#                 try:
#                     p = packet
#                     while p:
#                         layers.append(p.__class__.__name__)
#                         if p.payload == p or not hasattr(p, 'payload'):
#                             break
#                         p = p.payload
#                 except:
#                     layers = [packet.__class__.__name__]
#                 
#                 return jsonify({
#                     "status": "success",
#                     "message": "Packet built successfully",
#                     "summary": packet.summary(),
#                     "layers": layers,
#                     "length": len(packet),
#                     "hex": hex_str
#                 }), 200
#             else:
#                 return jsonify({
#                     "status": "error",
#                     "message": result if isinstance(result, str) else "Failed to build packet"
#                 }), 400
#         else:
#             return jsonify({
#                 "status": "error",
#                 "message": "Invalid packet configuration format"
#             }), 400
#             
#     except Exception as e:
#         return jsonify({
#             "status": "error",
#             "message": f"Error: {str(e)}"
#         }), 500

# --- API: Gửi gói tin tùy chỉnh (Phần 2 - Send Packet) ---
# PHẦN 2 - COMMENTED OUT
# @app.route('/api/send', methods=['POST'])
# def send_packet_api():
#     """
#     Gửi gói tin tùy chỉnh với cấu hình đầy đủ.
#     Tự động lưu gói tin đã gửi và phản hồi vào captured_packets.
#     """
#     try:
#         data = request.json or {}
#         print(f"\n[API] Received send request: dst={data.get('ip', {}).get('dst', 'N/A')}, proto={data.get('transport', {}).get('proto', 'N/A')}")
#         
#         if "ethernet" in data and "ip" in data and "transport" in data:
#             packet_config = {
#                 "ethernet": {
#                     "src": data["ethernet"].get("src") or "",
#                     "dst": data["ethernet"].get("dst") or "ff:ff:ff:ff:ff:ff",
#                     "type": data["ethernet"].get("type") or ""
#                 },
#                 "ip": {
#                     "src": data["ip"].get("src") or "",
#                     "dst": data["ip"].get("dst") or "",
#                     "ttl": int(data["ip"].get("ttl") or 64) if data["ip"].get("ttl") else 64
#                 },
#                 "protocol": data["transport"].get("proto", "ICMP").replace("v4", "").replace("v6", "").upper(),
#                 "payload": data.get("payload") or ""
#             }
#             
#             proto = packet_config["protocol"]
#             if proto == "ICMP":
#                 flags = data["transport"].get("flags", "")
#                 icmp_type = 8
#                 icmp_code = 0
#                 if "type=" in flags:
#                     try:
#                         icmp_type = int(flags.split("type=")[1].split()[0])
#                     except:
#                         pass
#                 if "code=" in flags:
#                     try:
#                         icmp_code = int(flags.split("code=")[1].split()[0])
#                     except:
#                         pass
#                 packet_config["icmp"] = {"type": icmp_type, "code": icmp_code}
#             elif proto == "TCP":
#                 sport_str = data["transport"].get("sport", "").strip()
#                 dport_str = data["transport"].get("dport", "").strip()
#                 tcp_config = {
#                     "dport": int(dport_str) if dport_str else 80,
#                     "flags": data["transport"].get("flags", "S")
#                 }
#                 if sport_str and sport_str != "0":
#                     try:
#                         tcp_config["sport"] = int(sport_str)
#                     except ValueError:
#                         pass
#                 packet_config["tcp"] = tcp_config
#             elif proto == "UDP":
#                 sport_str = data["transport"].get("sport", "").strip()
#                 dport_str = data["transport"].get("dport", "").strip()
#                 udp_config = {
#                     "dport": int(dport_str) if dport_str else 53
#                 }
#                 if sport_str and sport_str != "0":
#                     try:
#                         udp_config["sport"] = int(sport_str)
#                     except ValueError:
#                         pass
#                 packet_config["udp"] = udp_config
#             
#             interface = data.get("interface")
#             count = data.get("count", 1)
#             interval = data.get("interval", 0)
#             
#             success, result = send_custom_packet(
#                 packet_config,
#                 interface=interface,
#                 count=count,
#                 interval=interval
#             )
#         elif "packet_config" in data:
#             packet_config = data["packet_config"]
#             interface = data.get("interface")
#             count = data.get("count", 1)
#             interval = data.get("interval", 0)
#             
#             success, result = send_custom_packet(
#                 packet_config,
#                 interface=interface,
#                 count=count,
#                 interval=interval
#             )
#         else:
#             return jsonify({
#                 "status": "error",
#                 "message": "Invalid request format. Please use format with 'ethernet', 'ip', 'transport' or 'packet_config'."
#             }), 400
#         
#         if success:
#             return jsonify({
#                 "status": "success",
#                 "message": "Packet sent successfully",
#                 "data": result,
#                 "responses": result.get("responses", [])
#             }), 200
#         else:
#             return jsonify({
#                 "status": "error",
#                 "message": result if isinstance(result, str) else "Failed to send packet"
#             }), 400
#             
#     except Exception as e:
#         return jsonify({
#             "status": "error",
#             "message": f"Error: {str(e)}"
#         }), 500
# END PHẦN 2 - Send Packet API

# --- API: Health Check ---
@app.route('/api/health', methods=['GET'])
def health_check():
    """Kiểm tra trạng thái server."""
    try:
        current_interface = get_current_interface()
        interfaces = get_network_interfaces()
        
        return jsonify({
            "status": "success",
            "message": "Backend is running",
            "current_interface": current_interface,
            "available_interfaces": len(interfaces)
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

# --- API: Lấy thông tin interface hiện tại ---
@app.route('/api/interface/current', methods=['GET'])
def get_current_interface_api():
    """Lấy thông tin interface hiện tại."""
    try:
        current = get_current_interface()
        interfaces = get_network_interfaces()
        current_info = next((iface for iface in interfaces if iface["name"] == current), None)
        
        return jsonify({
            "status": "success",
            "interface": current,
            "info": current_info
        }), 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

if __name__ == '__main__':
    # Chạy server trên port mặc định 5000
    print("=" * 50)
    print("PacketCraft Backend Server")
    print("=" * 50)
    print(f"Server running on http://127.0.0.1:5000")
    print(f"Current interface: {get_current_interface()}")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)
