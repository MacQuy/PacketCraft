import * as Helper from "./helperFunction.js";
import * as Validation from "./validation.js";

const API_BASE = "http://127.0.0.1:5000/api";
let displayedPacketIds = new Set();

const tabs = [...document.querySelectorAll(".nav-link[data-target]")];
const panes = [...document.querySelectorAll(".tab-pane")];

function activateTab(key) {
    tabs.forEach((t) => t.classList.remove("active"));
    panes.forEach((p) => p.classList.add("d-none"));
    const tab = tabs.find((t) => t.dataset.tab === key) || tabs[0];
    tab.classList.add("active");
    const target = tab.dataset.target;
    const pane = document.querySelector(target);
    if (pane) pane.classList.remove("d-none");
    localStorage.setItem("nettools.activeTab", key);
}

tabs.forEach(t => t.addEventListener("click", (e) => {
    e.preventDefault();
    activateTab(t.dataset.tab);
    const sb = document.querySelector(".sidebar");
    if (sb.classList.contains("show")) sb.classList.remove("show");
    })
);

activateTab(localStorage.getItem("nettools.activeTab") || "dashboard");
document.querySelector("#menuToggle").addEventListener("click", () => document.querySelector(".sidebar").classList.toggle("show"));

document.querySelector('[data-go="build"]').addEventListener("click", () => activateTab("build"));
document.querySelector('[data-go="sniffer"]').addEventListener("click", () => activateTab("sniffer"));

function updateTransportFields() {
    const protoSelect = document.querySelector('select[name="proto"]');
    const sportInput = document.querySelector('input[name="sport"]');
    const dportInput = document.querySelector('input[name="dport"]');
    const flagsInput = document.querySelector('input[name="flags"]');
    const proto = protoSelect.value;
    
    if (proto === "ICMPv4" || proto === "ICMPv6") {
        if (sportInput) {
            sportInput.disabled = true;
            sportInput.placeholder = "N/A (ICMP)";
            sportInput.value = "";
        }
        if (dportInput) {
            dportInput.disabled = true;
            dportInput.placeholder = "N/A (ICMP)";
            dportInput.value = "";
        }
        if (flagsInput) {
            flagsInput.placeholder = "type=8 code=0 (Echo Request)";
            if (flagsInput.value && !flagsInput.value.includes("type=")) {
                if (flagsInput.value.match(/SYN|ACK|FIN|RST|PSH/i)) {
                    flagsInput.value = "type=8 code=0";
                    flagsInput.classList.add("is-warning");
                    setTimeout(() => flagsInput.classList.remove("is-warning"), 2000);
                }
            }
        }
    } else {
        if (sportInput) {
            sportInput.disabled = false;
            sportInput.placeholder = "";
        }
        if (dportInput) {
            dportInput.disabled = false;
            dportInput.placeholder = "";
        }
        if (flagsInput) {
            if (proto === "TCP") {
                flagsInput.placeholder = "SYN, SYN-ACK, ACK, RST, FIN, etc.";
            } else {
                flagsInput.placeholder = "N/A (UDP)";
            }
        }
    }
    const label = document.querySelector('label[for="flags"]') || document.querySelector('label').parentElement.querySelector('label');
    if (label) label.textContent = proto === "ICMPv4" || proto === "ICMPv6" ? "Type / Code" : "Flags / Type / Code";
}

document.addEventListener("DOMContentLoaded", () => {
    updateTransportFields();
    const protoSelect = document.querySelector('select[name="proto"]');
    if (protoSelect) {
        protoSelect.addEventListener("change", updateTransportFields);
    }
});

function renderLayered(obj) {
    let s = "";
    s += `Ethernet:\n  Src: ${obj.ethernet?.src || ""}\n  Dst: ${obj.ethernet?.dst || ""}\n  Type: ${obj.ethernet?.type || ""}\n\n`;
    s += `IP (v${obj.ip?.ver || "4"}):\n  Src: ${obj.ip?.src || ""}\n  Dst: ${obj.ip?.dst || ""}\n  TTL: ${obj.ip?.ttl || ""}\n\n`;
    s += `Transport (${obj.transport?.proto || ""}):\n`;
    if (obj.transport?.proto === "ICMPv4" || obj.transport?.proto === "ICMPv6") {
        s += `  Type/Code: ${obj.transport?.flags || ""}\n`;
    } else {
        s += `  SrcPort: ${obj.transport?.sport || ""}\n  DstPort: ${obj.transport?.dport || ""}\n  Flags: ${obj.transport?.flags || ""}\n`;
    }
    s += `\n`;
    const payload = obj.payload || "";
    s += `Payload (${payload.length} bytes):\n  ${payload}\n`;
    document.querySelector("#layerPreview").textContent = s;
}
  
function renderHex(obj) {
    const parts = [];
    parts.push(`ETH_SRC:${obj.ethernet?.src || ""}`);
    parts.push(`ETH_DST:${obj.ethernet?.dst || ""}`);
    parts.push(`IP_SRC:${obj.ip?.src || ""}`);
    parts.push(`IP_DST:${obj.ip?.dst || ""}`);
    parts.push(`PROTO:${obj.transport?.proto || ""}`);
    parts.push(`PAYLOAD:${obj.payload || ""}`);
    const joined = parts.join("|");
    document.querySelector("#hexPreview").textContent = Helper.toHex(joined);
}
  
document.querySelector("#btnBuild").addEventListener("click", async () => {
    const obj = gatherForm();
    const ifaceSelect = document.querySelector("#ifaceSelect");
    const selectedInterface = ifaceSelect.value;
    
    // Validate required fields
    if (!obj.ip.dst) {
        alert("Vui lòng nhập Destination IP để build packet!");
        return;
    }
    
    const btnBuild = document.querySelector("#btnBuild");
    const originalText = btnBuild.textContent;
    btnBuild.disabled = true;
    btnBuild.textContent = "Building...";
    
    try {
        const response = await fetch(`${API_BASE}/build`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                ...obj,
                interface: selectedInterface
            })
        });
        
        const data = await response.json();
        
        if (data.status === "success") {
            renderLayered(obj);
            renderHex(obj);
            const buildInfo = `Packet đã được build thành công!\n\n` +
                            `Summary: ${data.summary}\n` +
                            `Layers: ${data.layers.join(" / ")}\n` +
                            `Length: ${data.length} bytes`;
            if (data.hex) {
                document.querySelector("#hexPreview").textContent = data.hex;
            }
            alert(buildInfo);
        } else {
            alert(`Lỗi build packet: ${data.message}`);
        }
    } catch (error) {
        console.warn("Build API không khả dụng, chỉ preview:", error);
    renderLayered(obj);
    renderHex(obj);
        alert("Chế độ preview (API build không khả dụng). Packet sẽ được build khi Send.");
    } finally {
        btnBuild.disabled = false;
        btnBuild.textContent = originalText;
    }
});

document.querySelector("#btnSend").addEventListener("click", async () => {
    const obj = gatherForm();
    const ifaceSelect = document.querySelector("#ifaceSelect");
    const selectedInterface = ifaceSelect.value;
    
    if (!obj.ip.dst) {
        alert("Vui lòng nhập Destination IP!");
        return;
    }
    const proto = obj.transport?.proto || "";
    if (proto === "ICMPv4" || proto === "ICMPv6") {
        const flags = obj.transport?.flags || "";
        if (flags && !flags.match(/type=\d+\s+code=\d+/i)) {
            if (flags.match(/SYN|ACK|FIN|RST|PSH/i)) {
                alert("⚠️ Cảnh báo: ICMP không dùng TCP flags (SYN, ACK, etc.)!\n\n" +
                      "ICMP dùng Type/Code format:\n" +
                      "  - Echo Request: type=8 code=0\n" +
                      "  - Echo Reply: type=0 code=0\n\n" +
                      "Đã tự động sửa thành type=8 code=0");
                obj.transport.flags = "type=8 code=0";
            }
        }
        obj.transport.sport = "";
        obj.transport.dport = "";
    } else if (proto === "TCP") {
        const payload = obj.payload || "";
        const flags = obj.transport?.flags || "";
        if (payload && (payload.includes("GET") || payload.includes("POST") || payload.includes("HTTP"))) {
            if (flags === "SYN" || flags.includes("S")) {
                alert("⚠️ Cảnh báo: HTTP payload với SYN flag!\n\n" +
                      "SYN chỉ dùng để thiết lập kết nối, không gửi data.\n" +
                      "Để gửi HTTP, dùng PSH-ACK hoặc ACK.\n\n" +
                      "Đã tự động sửa thành PSH-ACK");
                obj.transport.flags = "PSH-ACK";
            }
        }
    }
    
    const btnSend = document.querySelector("#btnSend");
    const originalText = btnSend.textContent;
    btnSend.disabled = true;
    btnSend.textContent = "Sending...";
    
    try {
        const response = await fetch(`${API_BASE}/send`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                ...obj,
                interface: selectedInterface,
                count: 1
            })
        });
        
        const data = await response.json();
        
        if (data.status === "success") {
            alert(`Gói tin đã được gửi thành công!\n${data.message}`);
            await loadPackets();
        } else {
            alert(`Lỗi: ${data.message}`);
        }
    } catch (error) {
        alert(`Lỗi kết nối: ${error.message}\n\nĐảm bảo backend đang chạy tại http://127.0.0.1:5000`);
    } finally {
        btnSend.disabled = false;
        btnSend.textContent = originalText;
    }
});

function gatherForm() {
    const f = new FormData(document.querySelector("#packetForm"));
    const out = {
        ethernet: {
            src: f.get("eth_src"),
            dst: f.get("eth_dst"),
            type: f.get("eth_type"),
        },
        ip: {
            ver: f.get("ip_ver"),
            src: f.get("ip_src"),
            dst: f.get("ip_dst"),
            ttl: f.get("ip_ttl"),
        },
        transport: {
            proto: f.get("proto"),
            sport: f.get("sport"),
            dport: f.get("dport"),
            flags: f.get("flags"),
        },
        payload: f.get("payload")
    };
    return out;
}

document.querySelectorAll('input[name^="eth_"]').forEach(input => {
    input.addEventListener('input', e => {
        const { name, value } = e.target;
        let valid = true;
    
        if (name === 'eth_src' || name === 'eth_dst')
            valid = Validation.isValidMAC(value);
        else if (name === 'eth_type')
            valid = Validation.isValidType(value);
    
        e.target.classList.toggle('is-invalid', !valid);
        e.target.classList.toggle('is-valid', valid);
    });
});

document.querySelectorAll('input[name^="ip_"]').forEach(input => {
    input.addEventListener('input', e => {
        const version = document.querySelector('select[name="ip_ver"]').value;
        const { name, value } = e.target;
        let valid = true;

        if (name === 'ip_src' || name === 'ip_dst') {
            valid = Validation.isValidIP(value, version);
        } 
        else if (name === 'ip_ttl') {
            valid = Validation.isValidTTL(value);
        }

        e.target.classList.toggle('is-invalid', !valid);
        e.target.classList.toggle('is-valid', valid);
    });
});

let packetCounter = 0;

function getPacketInfo(pkt) {
    const proto = pkt.obj?.transport?.proto || "Unknown";
    const direction = pkt.direction || "";
    const payload = pkt.obj?.payload || "";
    
    let info = "";
    if (proto === "ICMP") {
        const flags = pkt.obj?.transport?.flags || "";
        if (flags.includes("type=8")) {
            info = "Echo (ping) request";
        } else if (flags.includes("type=0")) {
            info = "Echo (ping) reply";
        } else {
            info = `ICMP ${flags || "packet"}`;
        }
        if (payload && payload.length > 0) {
            const payloadPreview = payload.length > 30 ? payload.substring(0, 30) + "..." : payload;
            info += ` (${payload.length} bytes: ${payloadPreview})`;
        }
    } else if (proto === "TCP") {
        const flags = pkt.obj?.transport?.flags || "";
        const sport = pkt.obj?.transport?.sport || "";
        const dport = pkt.obj?.transport?.dport || "";
        
        if (flags.includes("SYN-ACK") || flags.includes("SA")) {
            info = `[SYN-ACK] ${sport} → ${dport}`;
        } else if (flags.includes("SYN") || flags.includes("S")) {
            info = `[SYN] ${sport} → ${dport}`;
        } else if (flags.includes("RST") || flags.includes("R")) {
            info = `[RST] ${sport} → ${dport}`;
        } else if (flags.includes("FIN") || flags.includes("F")) {
            info = `[FIN] ${sport} → ${dport}`;
        } else if (flags.includes("PSH-ACK") || flags.includes("PA")) {
            info = `[PSH-ACK] ${sport} → ${dport}`;
        } else if (flags.includes("ACK") || flags.includes("A")) {
            info = `[ACK] ${sport} → ${dport}`;
        } else {
            info = `${sport} → ${dport}`;
            if (flags) info += ` [${flags}]`;
        }
        
        // Thêm HTTP info nếu có
        if (payload && (payload.includes("GET") || payload.includes("POST") || payload.includes("HTTP"))) {
            const method = payload.match(/(GET|POST|PUT|DELETE|HEAD|OPTIONS)/)?.[0] || "";
            const path = payload.match(/\s+(\/[^\s]*)/)?.[1] || "";
            if (method) {
                info += ` ${method} ${path}`;
            } else {
                const payloadPreview = payload.length > 30 ? payload.substring(0, 30) + "..." : payload;
                info += ` (${payload.length} bytes)`;
            }
        } else if (payload && payload.length > 0) {
            const payloadPreview = payload.length > 30 ? payload.substring(0, 30) + "..." : payload;
            info += ` (${payload.length} bytes)`;
        }
    } else if (proto === "UDP") {
        const sport = pkt.obj?.transport?.sport || "";
        const dport = pkt.obj?.transport?.dport || "";
        info = `${sport} → ${dport}`;
        if (payload && payload.length > 0) {
            const payloadPreview = payload.length > 30 ? payload.substring(0, 30) + "..." : payload;
            info += ` (${payload.length} bytes: ${payloadPreview})`;
        }
    } else if (proto === "DNS") {
        const flags = pkt.obj?.transport?.flags || "";
        const sport = pkt.obj?.transport?.sport || "";
        const dport = pkt.obj?.transport?.dport || "";
        if (flags.includes("Query:")) {
            info = `Standard query ${flags.replace("Query:", "").trim()}`;
        } else if (flags.includes("Response:")) {
            info = `Standard query response ${flags.replace("Response:", "").trim()}`;
        } else {
            info = `DNS ${sport} → ${dport} ${flags}`;
        }
    } else {
        info = proto;
        if (payload && payload.length > 0) {
            const payloadPreview = payload.length > 30 ? payload.substring(0, 30) + "..." : payload;
            info += ` (${payload.length} bytes: ${payloadPreview})`;
        }
    }
    
    if (direction) {
        info = `[${direction}] ${info}`;
    }
    
    return info;
}

function getPacketLength(pkt) {
    if (pkt.hex) {
        const hexBytes = pkt.hex.split(" ").filter(x => x.trim()).length;
        if (hexBytes > 0) return hexBytes;
    }
    let length = 0;
    if (pkt.obj?.ethernet) length += 14;
    if (pkt.obj?.ip) length += 20;
    const proto = pkt.obj?.transport?.proto || "";
    if (proto === "TCP") length += 20;
    else if (proto === "UDP") length += 8;
    else if (proto === "ICMP") length += 8;
    const payload = pkt.obj?.payload || "";
    if (payload) length += payload.length;
    
    return length || 0;
}

function getPacketColorClass(pkt) {
    const proto = pkt.obj?.transport?.proto || "Unknown";
    const direction = pkt.direction || "";
    
    if (direction === "sent") {
        return "table-primary";
    } else if (direction === "received") {
        return "table-success";
    } else if (direction === "sniffed") {
        return "table-warning";
    }
    
    if (proto === "ICMP") return "table-info";
    if (proto === "TCP") return "";
    if (proto === "UDP") return "table-secondary";
    
    return "";
}

function formatPacketDetails(pkt) {
    const packetLength = getPacketLength(pkt);
    const arrivalTime = pkt.ts ? new Date(pkt.ts) : null;
    
    let html = '<div class="packet-details" style="font-family: monospace; font-size: 0.9rem; white-space: nowrap;">';
    
    // Frame details
    html += '<details><summary style="font-weight: bold; cursor: pointer; white-space: nowrap;">Frame ' + (pkt.id || "N/A") + '</summary>';
    html += '<div style="margin-left: 20px; margin-top: 5px; white-space: nowrap;">';
    if (arrivalTime) {
        html += `  Arrival Time: ${arrivalTime.toLocaleString('en-US', { timeZone: 'Asia/Ho_Chi_Minh' })}<br>`;
        html += `  Epoch Time: ${(pkt.ts / 1000).toFixed(6)} seconds<br>`;
    }
    html += `  Frame Number: ${pkt.id || "N/A"}<br>`;
    html += `  Frame Length: ${packetLength} bytes (${packetLength * 8} bits)<br>`;
    const protocols = [];
    if (pkt.obj?.ethernet) protocols.push("eth");
    if (pkt.obj?.ip) protocols.push("ip");
    if (pkt.obj?.transport) {
        const proto = pkt.obj.transport.proto?.toLowerCase() || "";
        if (proto === "tcp") protocols.push("tcp");
        else if (proto === "udp") protocols.push("udp");
        else if (proto === "icmp") protocols.push("icmp");
        else if (proto === "dns") protocols.push("dns");
    }
    if (pkt.obj?.payload) protocols.push("data");
    html += `  Protocols in frame: ${protocols.join(":")}<br>`;
    html += '</div></details>';
    
    // Ethernet II details
    if (pkt.obj?.ethernet) {
        const eth = pkt.obj.ethernet;
        const srcMac = eth.src || "N/A";
        const dstMac = eth.dst || "N/A";
        const ethType = eth.type ? (typeof eth.type === 'string' ? parseInt(eth.type) : eth.type) : 0;
        const ethTypeHex = ethType ? `0x${ethType.toString(16).padStart(4, '0')}` : "N/A";
        const ethTypeName = ethType === 2048 ? "IPv4" : ethType === 34525 ? "IPv6" : ethType ? ethTypeHex : "N/A";
        
        html += '<details><summary style="font-weight: bold; cursor: pointer; white-space: nowrap;">Ethernet II, Src: ' + srcMac + ', Dst: ' + dstMac + '</summary>';
        html += '<div style="margin-left: 20px; margin-top: 5px; white-space: nowrap;">';
        html += `  Destination: ${dstMac}<br>`;
        html += `  Source: ${srcMac}<br>`;
        html += `  Type: ${ethTypeHex} (${ethTypeName})<br>`;
        html += '</div></details>';
    }
    
    if (pkt.obj?.ip) {
        const ip = pkt.obj.ip;
        const version = ip.version || 4;
        const ihl = ip.ihl || 5;
        const tos = ip.tos || 0;
        const len = ip.len || 0;
        const id = ip.id || 0;
        const flags = ip.flags || 0;
        const frag = ip.frag || 0;
        const ttl = ip.ttl || 0;
        const proto = ip.proto || 0;
        const chksum = ip.chksum || 0;
        
        const protoName = proto === 6 ? "TCP" : proto === 17 ? "UDP" : proto === 1 ? "ICMP" : `Unknown (${proto})`;
        html += '<details><summary style="font-weight: bold; cursor: pointer; white-space: nowrap;">Internet Protocol Version ' + version + ', Src: ' + (ip.src || "N/A") + ', Dst: ' + (ip.dst || "N/A") + '</summary>';
        html += '<div style="margin-left: 20px; margin-top: 5px; white-space: nowrap;">';
        html += `  Version: ${version}<br>`;
        html += `  Header Length: ${ihl * 4} bytes (${ihl})<br>`;
        const dscp = Math.floor(tos / 4);
        const ecn = tos & 0x3;
        const ecnStr = ecn === 0 ? "Not-ECT" : ecn === 1 ? "ECT(1)" : ecn === 2 ? "ECT(0)" : "CE";
        html += `  Differentiated Services Field: 0x${tos.toString(16).padStart(2, '0')} (DSCP: ${dscp}, ECN: ${ecnStr})<br>`;
        html += `  Total Length: ${len}<br>`;
        html += `  Identification: 0x${id.toString(16).padStart(4, '0')} (${id})<br>`;
        const df = (flags & 0x4000) !== 0;
        const mf = (flags & 0x2000) !== 0;
        html += `  Flags: 0x${(flags & 0xE000).toString(16).padStart(4, '0')} (Don't fragment: ${df ? "Set" : "Not set"}, More fragments: ${mf ? "Set" : "Not set"})<br>`;
        html += `  Fragment Offset: ${frag}<br>`;
        html += `  Time to Live: ${ttl}<br>`;
        html += `  Protocol: ${protoName} (${proto})<br>`;
        html += `  Header Checksum: 0x${chksum.toString(16).padStart(4, '0')}<br>`;
        html += `  Source Address: ${ip.src || "N/A"}<br>`;
        html += `  Destination Address: ${ip.dst || "N/A"}<br>`;
        html += '</div></details>';
    }
    
    if (pkt.obj?.transport) {
        const proto = pkt.obj.transport.proto;
        if (proto === "TCP") {
            const sport = pkt.obj.transport.sport || "N/A";
            const dport = pkt.obj.transport.dport || "N/A";
            const seq = pkt.obj.transport.seq || 0;
            const ack = pkt.obj.transport.ack || 0;
            const dataofs = pkt.obj.transport.tcp_dataofs || 5;
            const flags = pkt.obj.transport.flags || "";
            const win = pkt.obj.transport.win || 0;
            const chksum = pkt.obj.transport.tcp_chksum || 0;
            const urgptr = pkt.obj.transport.tcp_urgptr || 0;
            
            const tcpFlagsNum = pkt.obj.transport.tcp_flags || 0;
            const tcpLen = pkt.length ? (pkt.length - (dataofs * 4 + 20)) : 0;
            html += '<details><summary style="font-weight: bold; cursor: pointer; white-space: nowrap;">Transmission Control Protocol, Src Port: ' + sport + ', Dst Port: ' + dport + '</summary>';
            html += '<div style="margin-left: 20px; margin-top: 5px; white-space: nowrap;">';
            html += `  Source Port: ${sport}<br>`;
            html += `  Destination Port: ${dport}<br>`;
            html += `  Sequence Number: ${seq}<br>`;
            if (ack > 0) {
                html += `  Acknowledgment Number: ${ack}<br>`;
            }
            html += `  Header Length: ${dataofs * 4} bytes (${dataofs})<br>`;
            const fin = (tcpFlagsNum & 0x01) !== 0;
            const syn = (tcpFlagsNum & 0x02) !== 0;
            const rst = (tcpFlagsNum & 0x04) !== 0;
            const psh = (tcpFlagsNum & 0x08) !== 0;
            const ackFlag = (tcpFlagsNum & 0x10) !== 0;
            const urg = (tcpFlagsNum & 0x20) !== 0;
            const flagsSummary = [];
            if (fin) flagsSummary.push("FIN");
            if (syn) flagsSummary.push("SYN");
            if (rst) flagsSummary.push("RST");
            if (psh) flagsSummary.push("PSH");
            if (ackFlag) flagsSummary.push("ACK");
            if (urg) flagsSummary.push("URG");
            html += `  Flags: 0x${(tcpFlagsNum & 0x1FF).toString(16).padStart(3, '0')} (${flagsSummary.length > 0 ? flagsSummary.join(", ") : "None"})<br>`;
            html += `  Window: ${win}<br>`;
            html += `  Checksum: 0x${chksum.toString(16).padStart(4, '0')}<br>`;
            if (urgptr > 0) {
                html += `  Urgent Pointer: ${urgptr}<br>`;
            }
            const optionsLen = (dataofs * 4) - 20;
            if (optionsLen > 0) {
                const options = [];
                if (pkt.obj.transport.tcp_mss) {
                    options.push(`Maximum segment size: ${pkt.obj.transport.tcp_mss}`);
                }
                if (pkt.obj.transport.tcp_wscale) {
                    options.push(`Window scale: ${pkt.obj.transport.tcp_wscale}`);
                }
                if (pkt.obj.transport.tcp_sack_perm) {
                    options.push(`SACK permitted`);
                }
                if (options.length > 0) {
                    html += `  Options: (${optionsLen} bytes)<br>`;
                    options.forEach(opt => html += `    ${opt}<br>`);
                }
            }
            if (tcpLen > 0) {
                html += `  TCP Segment Len: ${tcpLen}<br>`;
            }
            html += '</div></details>';
        } else if (proto === "UDP") {
            const sport = pkt.obj.transport.sport || "N/A";
            const dport = pkt.obj.transport.dport || "N/A";
            const len = pkt.obj.transport.udp_len || 0;
            const chksum = pkt.obj.transport.udp_chksum || 0;
            
            html += '<details><summary style="font-weight: bold; cursor: pointer; white-space: nowrap;">User Datagram Protocol, Src Port: ' + sport + ', Dst Port: ' + dport + '</summary>';
            html += '<div style="margin-left: 20px; margin-top: 5px; white-space: nowrap;">';
            html += `  Source Port: ${sport}<br>`;
            html += `  Destination Port: ${dport}<br>`;
            html += `  Length: ${len}<br>`;
            html += `  Checksum: 0x${chksum.toString(16).padStart(4, '0')}<br>`;
            html += '</div></details>';
        } else if (proto === "ICMP") {
            const icmpType = pkt.obj.transport.icmp_type || 0;
            const icmpCode = pkt.obj.transport.icmp_code || 0;
            const typeName = icmpType === 0 ? "Echo Reply" : icmpType === 8 ? "Echo Request" : icmpType === 3 ? "Destination Unreachable" : icmpType === 11 ? "Time Exceeded" : `Type ${icmpType}`;
            html += '<details><summary style="font-weight: bold; cursor: pointer; white-space: nowrap;">Internet Control Message Protocol</summary>';
            html += '<div style="margin-left: 20px; margin-top: 5px; white-space: nowrap;">';
            html += `  Type: ${icmpType} (${typeName})<br>`;
            html += `  Code: ${icmpCode}<br>`;
            html += '</div></details>';
        } else if (proto === "DNS") {
            html += '<details><summary style="font-weight: bold; cursor: pointer; white-space: nowrap;">Domain Name System</summary>';
            html += '<div style="margin-left: 20px; margin-top: 5px; white-space: nowrap;">';
            html += `  ${pkt.obj.transport.flags || "DNS packet"}<br>`;
            html += '</div></details>';
        }
    }
    
    if (pkt.obj?.arp && pkt.obj.arp.op !== undefined) {
        const arp = pkt.obj.arp;
        const opName = arp.op === 1 ? "Request (who-has)" : arp.op === 2 ? "Reply (is-at)" : `Opcode ${arp.op}`;
        html += '<details><summary style="font-weight: bold; cursor: pointer; white-space: nowrap;">Address Resolution Protocol (' + opName + ')</summary>';
        html += '<div style="margin-left: 20px; margin-top: 5px; white-space: nowrap;">';
        html += `  Opcode: ${arp.op} (${opName})<br>`;
        if (pkt.obj.ip?.src) html += `  Sender IP: ${pkt.obj.ip.src}<br>`;
        if (pkt.obj.ip?.dst) html += `  Target IP: ${pkt.obj.ip.dst}<br>`;
        if (arp.hwsrc) html += `  Sender MAC: ${arp.hwsrc}<br>`;
        if (arp.hwdst) html += `  Target MAC: ${arp.hwdst}<br>`;
        html += '</div></details>';
    }
    
    if (pkt.obj?.payload && pkt.obj.payload.length > 0) {
        html += '<details><summary style="font-weight: bold; cursor: pointer;">Data (' + pkt.obj.payload.length + ' bytes)</summary>';
        html += '<div style="margin-left: 20px; margin-top: 5px; word-break: break-all;">';
        const payloadPreview = pkt.obj.payload.length > 500 ? pkt.obj.payload.substring(0, 500) + "..." : pkt.obj.payload;
        html += payloadPreview.replace(/\n/g, '<br>');
        html += '</div></details>';
    }
    
    if (pkt.hex) {
        html += '<details><summary style="font-weight: bold; cursor: pointer;">Hex Dump</summary>';
        html += '<div style="margin-left: 20px; margin-top: 5px; font-family: monospace;">';
        const hexLines = pkt.hex.match(/.{1,48}/g) || [];
        hexLines.forEach((line, idx) => {
            const offset = (idx * 16).toString(16).padStart(8, '0');
            html += `  ${offset}  ${line.match(/.{1,2}/g)?.join(' ') || line}<br>`;
        });
        html += '</div></details>';
    }
    
    html += '</div>';
    return html;
}

function updateStatistics() {
    const packets = Array.from(document.querySelectorAll("#sniffTable tr"));
    let total = packets.length;
    let sent = 0, received = 0, sniffed = 0;
    
    packets.forEach(tr => {
        const info = tr.cells[6]?.textContent || "";
        if (info.includes("[sent]")) sent++;
        else if (info.includes("[received]")) received++;
        else if (info.includes("[sniffed]")) sniffed++;
    });
    
    const statTotal = document.querySelector("#statTotal");
    const statSent = document.querySelector("#statSent");
    const statReceived = document.querySelector("#statReceived");
    const statSniffed = document.querySelector("#statSniffed");
    
    if (statTotal) statTotal.textContent = total;
    if (statSent) statSent.textContent = sent;
    if (statReceived) statReceived.textContent = received;
    if (statSniffed) statSniffed.textContent = sniffed;
}

function filterPackets(filterText) {
    const rows = Array.from(document.querySelectorAll("#sniffTable tr"));
    if (!filterText || filterText.trim() === "") {
        rows.forEach(row => row.style.display = "");
        return;
    }
    
    const filter = filterText.toLowerCase();
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(filter) ? "" : "none";
    });
}

function addSniffRow(pkt) {
    if (pkt.id && displayedPacketIds.has(pkt.id)) {
        return;
    }
    if (pkt.id) {
        displayedPacketIds.add(pkt.id);
    }
    
    packetCounter++;
    
    const tr = document.createElement("tr");
    tr.className = getPacketColorClass(pkt);
    
    const no = packetCounter;
    const t = pkt.ts ? new Date(pkt.ts).toLocaleTimeString() + "." + String(pkt.ts % 1000).padStart(3, '0') : (pkt.time || "N/A");
    const proto = pkt.obj?.transport?.proto || (pkt.obj?.arp ? "ARP" : "Unknown");
    const src = proto === "ARP" ? (pkt.obj?.ip?.src || "N/A") : (pkt.obj?.ip?.src || pkt.obj?.ethernet?.src || "N/A");
    const dst = proto === "ARP" ? (pkt.obj?.ip?.dst || "N/A") : (pkt.obj?.ip?.dst || pkt.obj?.ethernet?.dst || "N/A");
    const length = getPacketLength(pkt);
    const info = getPacketInfo(pkt);
    
    tr.innerHTML = `<td>${no}</td><td>${t}</td><td>${src}</td><td>${dst}</td><td>${proto}</td><td>${length}</td><td>${info}</td>`;
    
    tr.addEventListener("click", () => {
        const details = formatPacketDetails(pkt);
        const modalDetail = document.querySelector("#modalDetail");
        if (modalDetail) modalDetail.innerHTML = details;
        const modal = document.querySelector("#detailModal");
        if (modal) {
            const bsModal = new bootstrap.Modal(modal);
            bsModal.show();
        }
        document.querySelectorAll("#sniffTable tr").forEach(r => r.classList.remove("table-active"));
        tr.classList.add("table-active");
    });
    
    document.querySelector("#sniffTable").appendChild(tr);
    updateStatistics();
}

async function loadPackets() {
    try {
        const response = await fetch(`${API_BASE}/sniff/packets`);
        const data = await response.json();
        
        if (data.status === "success" && data.packets) {
            document.querySelector("#sniffTable").innerHTML = "";
            displayedPacketIds.clear();
            packetCounter = 0;
            data.packets.forEach(pkt => addSniffRow(pkt));
            const filterInput = document.querySelector("#packetFilter");
            if (filterInput && filterInput.value) filterPackets(filterInput.value);
        }
    } catch (error) {
        console.error("Error loading packets:", error);
    }
}

async function checkSniffingStatus() {
    try {
        const response = await fetch(`${API_BASE}/sniff/status`);
        const data = await response.json();
        if (data.status === "success") {
            isSniffing = data.is_sniffing;
            if (isSniffing) {
                document.querySelector("#btnStartSniff").disabled = true;
                document.querySelector("#btnStopSniff").disabled = false;
            } else {
                document.querySelector("#btnStartSniff").disabled = false;
                document.querySelector("#btnStopSniff").disabled = true;
            }
        }
    } catch (error) {
        console.error("Error checking sniffing status:", error);
        isSniffing = false;
    }
    return Promise.resolve();
}

let packetRefreshInterval = null;
tabs.forEach(t => {
    t.addEventListener("click", () => {
        const tabKey = t.dataset.tab;
        if (tabKey === "sniffer") {
            checkSniffingStatus().then(() => {
                if (isSniffing) {
                    loadPackets();
                    if (packetRefreshInterval) clearInterval(packetRefreshInterval);
                    packetRefreshInterval = setInterval(loadPackets, 2000);
                } else {
                    if (packetRefreshInterval) {
                        clearInterval(packetRefreshInterval);
                        packetRefreshInterval = null;
                    }
                }
            });
        } else {
            if (packetRefreshInterval) {
                clearInterval(packetRefreshInterval);
                packetRefreshInterval = null;
            }
        }
    });
});

let isSniffing = false;

document.querySelector("#btnStartSniff").addEventListener("click", async () => {
    if (isSniffing) {
        if (confirm("Sniffing is already in progress. Do you want to stop and restart with new settings?")) {
            try {
                const stopResponse = await fetch(`${API_BASE}/sniff/stop`, { method: "POST" });
                const stopData = await stopResponse.json();
                if (stopData.status === "success") {
                    isSniffing = false;
                    document.querySelector("#btnStartSniff").disabled = false;
                    document.querySelector("#btnStopSniff").disabled = true;
                }
            } catch (e) {
                console.error("Error stopping:", e);
            }
        } else {
            return;
        }
    }
    
    const filterInput = document.querySelector("#packetFilter");
    const filter = filterInput ? filterInput.value.trim() : "";
    const ifaceSelect = document.querySelector("#ifaceSelect");
    const selectedInterface = ifaceSelect ? ifaceSelect.value : "";
    
    try {
        const response = await fetch(`${API_BASE}/sniff/start`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                filter: filter,
                interface: selectedInterface
            })
        });
        
        const data = await response.json();
        if (data.status === "success") {
            isSniffing = true;
            document.querySelector("#btnStartSniff").disabled = true;
            document.querySelector("#btnStopSniff").disabled = false;
            loadPackets();
            if (packetRefreshInterval) clearInterval(packetRefreshInterval);
            packetRefreshInterval = setInterval(loadPackets, 2000);
        } else {
            alert(`❌ Error: ${data.message}\n\nIf sniffing is already running, click "Stop Capture" first.`);
        }
    } catch (error) {
        alert(`❌ Error starting sniffing: ${error.message}\n\nMake sure backend is running at http://127.0.0.1:5000`);
    }
});

document.querySelector("#btnStopSniff").addEventListener("click", async () => {
    try {
        const response = await fetch(`${API_BASE}/sniff/stop`, {
            method: "POST"
        });
        
        const data = await response.json();
        if (data.status === "success") {
            isSniffing = false;
            document.querySelector("#btnStartSniff").disabled = false;
            document.querySelector("#btnStopSniff").disabled = true;
            if (packetRefreshInterval) {
                clearInterval(packetRefreshInterval);
                packetRefreshInterval = null;
            }
            alert(`✅ Sniffing stopped!\n\n${data.message}`);
        } else {
            alert(`❌ Error: ${data.message}`);
        }
    } catch (error) {
        alert(`❌ Error stopping sniffing: ${error.message}`);
    }
});

document.querySelector("#btnApplyFilter")?.addEventListener("click", () => {
    const filterInput = document.querySelector("#packetFilter");
    if (filterInput) {
        filterPackets(filterInput.value);
    }
});

document.querySelector("#btnClearFilter")?.addEventListener("click", () => {
    const filterInput = document.querySelector("#packetFilter");
    if (filterInput) {
        filterInput.value = "";
        filterPackets("");
    }
});

document.querySelector("#packetFilter")?.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
        document.querySelector("#btnApplyFilter")?.click();
    }
});

document.querySelector("#clearSniff").addEventListener("click", async () => {
    try {
        const response = await fetch(`${API_BASE}/sniff/clear`, {
            method: "POST"
        });
        const data = await response.json();
        
        if (data.status === "success") {
            document.querySelector("#sniffTable").innerHTML = "";
            displayedPacketIds.clear();
        }
    } catch (error) {
        console.error("Error clearing packets:", error);
    document.querySelector("#sniffTable").innerHTML = "";
        displayedPacketIds.clear();
    }
});

const builtinTemplates = [
    {
      name: "Ping (ICMP)",
      proto: "ICMPv4",
      eth: {},
      ip: { ver: 4, src: "192.168.0.100", dst: "192.168.0.1", ttl: 64 },
      transport: { sport: "", dport: "", flags: "type=8 code=0" },
      payload: "ping",
    },
    {
      name: "TCP SYN",
      proto: "TCP",
      eth: {},
      ip: { ver: 4, src: "192.168.0.100", dst: "192.168.0.1", ttl: 64 },
      transport: { sport: "40000", dport: "80", flags: "SYN" },
      payload: "",
    },
    {
      name: "HTTP GET",
      proto: "TCP",
      eth: {},
      ip: { ver: 4, src: "192.168.0.100", dst: "93.184.216.34", ttl: 64 },
      transport: { sport: "40001", dport: "80", flags: "SYN" },
      payload: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    },
];
  
function renderTemplates(list) {
    const ul = document.querySelector("#templateList");
    ul.innerHTML = "";
    list.forEach((t, idx) => {
        const li = document.createElement("li");
        li.className =
        "list-group-item d-flex justify-content-between align-items-center";
        li.innerHTML = `
        <div>
            <strong>${t.name}</strong>
            <div class="small text-muted">${t.proto}</div>
        </div>
        <div class="btn-group btn-group-sm">
            <button class="btn btn-sm btn-outline-primary" data-load="${idx}">Load</button>
            <button class="btn btn-sm btn-outline-secondary" data-export="${idx}">Export</button>
        </div>
        `;
        ul.appendChild(li);
        li.querySelector("[data-load]").addEventListener("click", () => applyTemplate(t));
        li.querySelector("[data-export]").addEventListener("click", () => downloadJSON(t, t.name.replace(/\s+/g, "_") + ".json"));
    });
}

document.querySelector("#loadBuiltin").addEventListener("click", () => renderTemplates(builtinTemplates));

function applyTemplate(template) {
    if (template.eth) {
        if (template.eth.src) document.querySelector('input[name="eth_src"]').value = template.eth.src;
        if (template.eth.dst) document.querySelector('input[name="eth_dst"]').value = template.eth.dst;
    }
    if (template.ip) {
        if (template.ip.ver) document.querySelector('select[name="ip_ver"]').value = template.ip.ver;
        if (template.ip.src) document.querySelector('input[name="ip_src"]').value = template.ip.src;
        if (template.ip.dst) document.querySelector('input[name="ip_dst"]').value = template.ip.dst;
        if (template.ip.ttl) document.querySelector('input[name="ip_ttl"]').value = template.ip.ttl;
    }
    if (template.transport) {
        if (template.transport.proto) document.querySelector('select[name="proto"]').value = template.transport.proto;
        if (template.transport.sport) document.querySelector('input[name="sport"]').value = template.transport.sport;
        if (template.transport.dport) document.querySelector('input[name="dport"]').value = template.transport.dport;
        if (template.transport.flags) document.querySelector('input[name="flags"]').value = template.transport.flags;
    }
    if (template.payload !== undefined) {
        document.querySelector('textarea[name="payload"]').value = template.payload;
    }
    document.querySelector("#btnBuild").click();
}

function downloadJSON(data, filename) {
    const jsonStr = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

document.querySelector("#btnSaveJson").addEventListener("click", () => {
    const obj = gatherForm();
    downloadJSON(obj, "packet_config.json");
});

document.querySelector("#btnLoadJson").addEventListener("click", () => {
    document.querySelector("#loadJsonFile").click();
});

document.querySelector("#loadJsonFile").addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = (event) => {
        try {
            const obj = JSON.parse(event.target.result);
            if (obj.ethernet) {
                if (obj.ethernet.src) document.querySelector('input[name="eth_src"]').value = obj.ethernet.src;
                if (obj.ethernet.dst) document.querySelector('input[name="eth_dst"]').value = obj.ethernet.dst;
                if (obj.ethernet.type) document.querySelector('input[name="eth_type"]').value = obj.ethernet.type;
            }
            if (obj.ip) {
                if (obj.ip.ver) document.querySelector('select[name="ip_ver"]').value = obj.ip.ver;
                if (obj.ip.src) document.querySelector('input[name="ip_src"]').value = obj.ip.src;
                if (obj.ip.dst) document.querySelector('input[name="ip_dst"]').value = obj.ip.dst;
                if (obj.ip.ttl) document.querySelector('input[name="ip_ttl"]').value = obj.ip.ttl;
            }
            if (obj.transport) {
                if (obj.transport.proto) document.querySelector('select[name="proto"]').value = obj.transport.proto;
                if (obj.transport.sport) document.querySelector('input[name="sport"]').value = obj.transport.sport;
                if (obj.transport.dport) document.querySelector('input[name="dport"]').value = obj.transport.dport;
                if (obj.transport.flags) document.querySelector('input[name="flags"]').value = obj.transport.flags;
            }
            if (obj.payload !== undefined) {
                document.querySelector('textarea[name="payload"]').value = obj.payload;
            }
            document.querySelector("#btnBuild").click();
        } catch (error) {
            alert("Lỗi đọc file JSON: " + error.message);
        }
    };
    reader.readAsText(file);
});

let batchInterval = null;
let batchCount = 0;
let batchTotal = 0;
let batchReceived = 0;

document.querySelector("#startBatch").addEventListener("click", async () => {
    const obj = gatherForm();
    if (!obj.ip.dst) {
        alert("Vui lòng nhập Destination IP!");
        return;
    }
    
    const count = parseInt(document.querySelector("#batchCount").value) || 10;
    const rate = parseFloat(document.querySelector("#batchRate").value) || 5;
    const interval = 1000 / rate;
    const ifaceSelect = document.querySelector("#ifaceSelect");
    const selectedInterface = ifaceSelect.value;
    
    const btnStart = document.querySelector("#startBatch");
    const btnStop = document.querySelector("#stopBatch");
    btnStart.disabled = true;
    btnStop.disabled = false;
    
    batchTotal = count;
    batchCount = 0;
    batchReceived = 0;
    document.querySelector("#statSent").textContent = "0";
    document.querySelector("#statRecv").textContent = "0";
    document.querySelector("#statLoss").textContent = "0";
    
    const sendPacket = async () => {
        if (batchCount >= batchTotal) {
            stopBatch();
            return;
        }
        
        try {
            const response = await fetch(`${API_BASE}/send`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    ...obj,
                    interface: selectedInterface,
                    count: 1
                })
            });
            
            const data = await response.json();
            if (data.status === "success") {
                batchCount++;
                if (data.data && data.data.responses && data.data.responses.length > 0) {
                    batchReceived++;
                }
                document.querySelector("#statSent").textContent = batchCount;
                document.querySelector("#statRecv").textContent = batchReceived;
                const loss = batchCount > 0 ? Math.round((1 - batchReceived / batchCount) * 100) : 0;
                document.querySelector("#statLoss").textContent = loss;
            }
        } catch (error) {
            console.error("Error sending batch packet:", error);
        }
    };
    await sendPacket();
    batchInterval = setInterval(sendPacket, interval);
});

function stopBatch() {
    if (batchInterval) {
        clearInterval(batchInterval);
        batchInterval = null;
    }
    document.querySelector("#startBatch").disabled = false;
    document.querySelector("#stopBatch").disabled = true;
}

document.querySelector("#stopBatch").addEventListener("click", stopBatch);

async function loadInterfaces() {
    try {
        const response = await fetch(`${API_BASE}/interfaces`);
        const data = await response.json();
        
        if (data.status === "success" && data.interfaces) {
            const ifaceSelect = document.querySelector("#ifaceSelect");
            ifaceSelect.innerHTML = "";
            
            data.interfaces.forEach(iface => {
                const option = document.createElement("option");
                option.value = iface.name;
                option.textContent = `${iface.name} (${iface.ip})`;
                if (iface.name === data.current) {
                    option.selected = true;
                }
                ifaceSelect.appendChild(option);
            });
        }
    } catch (error) {
        console.error("Error loading interfaces:", error);
    }
}
loadInterfaces();
