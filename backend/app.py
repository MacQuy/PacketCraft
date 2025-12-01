from flask import Flask, request, jsonify
from scapy.all import IP, UDP, TCP, ICMP, Raw, send

app = Flask(__name__)

@app.route("/packet/send", methods=["POST"])
def send_packet():
    data = request.json

    src = data.get("src")
    dst = data.get("dst")
    proto = data.get("protocol")
    sport = data.get("sport")
    dport = data.get("dport")
    payload = data.get("payload", "")

    ip = IP(src=src, dst=dst)

    if proto == "UDP":
        pkt = ip / UDP(sport=int(sport), dport=int(dport)) / Raw(load=payload)
    elif proto == "TCP":
        pkt = ip / TCP(sport=int(sport), dport=int(dport)) / Raw(load=payload)
    elif proto == "ICMP":
        pkt = ip / ICMP() / Raw(load=payload)
    else:
        return jsonify({"error": "Unsupported protocol"}), 400

    send(pkt, verbose=False)

    return jsonify({
        "status": "sent",
        "summary": pkt.summary()
    })

@app.route("/packet/build", methods=["POST"])
def build_packet():
    data = request.json

    src = data.get("src")
    dst = data.get("dst")
    proto = data.get("protocol")
    sport = data.get("sport")
    dport = data.get("dport")
    payload = data.get("payload", "")

    ip = IP(src=src, dst=dst)

    if proto == "UDP":
        pkt = ip / UDP(sport=int(sport), dport=int(dport)) / Raw(load=payload)
    elif proto == "TCP":
        pkt = ip / TCP(sport=int(sport), dport=int(dport)) / Raw(load=payload)
    elif proto == "ICMP":
        pkt = ip / ICMP() / Raw(load=payload)
    else:
        return jsonify({"error": "Unsupported protocol"}), 400

    return jsonify({
        "hex": bytes(pkt).hex(),
        "summary": pkt.summary()
    })

@app.route('/sort', methods=['POST'])
def sort():
    data = request.json
    items = data.get("items")

    if not isinstance(items, list):
        return jsonify({"error": "Please provide a list under 'items'"}), 400

    try:
        sorted_items = sorted(items)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({"sorted": sorted_items})

if __name__ == '__main__':
    app.run(port=5000)