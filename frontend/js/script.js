import * as Helper from "./helperFunction.js";
import * as Validation from "./validation.js";
import * as Template from "./templates.js";

const packetStore = { sent: [], received: [] }; // in-memory for PCAP export

// ---------- Tab handling ----------
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

// ---------- Building UI handling ----------
document.querySelector("#networkProtocol").addEventListener("change", e => {
    const val = e.target.value;
    document.querySelector("#ipv4").style.display = val === "0x0800" ? "block" : "none";
    document.querySelector("#ipv6").style.display = val === "0x86DD" ? "block" : "none";
    document.querySelector("#arp").style.display = val === "0x0806" ? "block" : "none";
});

document.querySelector("#protoSelect").addEventListener("change", e => {
    const val = e.target.value;

    document.querySelector("#sport_div").style.display = (val === "tcp" || val === "udp") ? "block" : "none";
    document.querySelector("#dport_div").style.display = (val === "tcp" || val === "udp") ? "block" : "none";
    document.querySelector("#seq_div").style.display = val === "tcp" ? "block" : "none";
    document.querySelector("#ack_div").style.display = val === "tcp" ? "block" : "none";
    document.querySelector("#tcp_flags_div").style.display = val === "tcp" ? "block" : "none";
    document.querySelector("#type_div").style.display = val === "icmp" ? "block" : "none";
    document.querySelector("#code_div").style.display = val === "icmp" ? "block" : "none";
});

// ---------- Build Packet ----------
function formatObject(obj, indent = "") {
    let result = "";
    for (const [key, value] of Object.entries(obj)) {
        if (typeof value === "object" && value !== null) {
            result += `${indent}${key}:\n` + formatObject(value, indent);
        } else {
            result += `${indent}${key}: ${value ?? ""}\n`;
        }
    }
  
    return result;
}

function renderLayered(obj) {
    const s = formatObject(obj);
    document.querySelector("#layerPreview").textContent = s;
}
  
document.querySelector("#btnBuild").addEventListener("click", () => {
    const obj = gatherForm();
    renderLayered(obj);
});

function gatherForm() {
    const f = new FormData(document.querySelector("#packetForm"));
    const Ethernet= {
        SrcMAC: f.get("eth_src"),
        DstMAC: f.get("eth_dst"),
        Type: f.get("eth_type"),
    }
    let Payload = f.get("payload");
    const IPv4 = {
        SrcIPv4: f.get("ipv4_src"),
        DstIPv4: f.get("ipv4_dst"),
        TTL: f.get("ipv4_ttl"),
        IPID: f.get("ip_id"),
        Flags: f.get("flags"),
    }
    const IPv6 = {
        SrcIPv6: f.get("ipv6_src"),
        DstIPv6: f.get("ipv6_dst"),
    }
    const ARP = {
        Op: f.get("op"),
        SrcIP: f.get("ip_arp_src"),
        DstIP: f.get("ip_arp_dst"),
    }
    const TCP = {
        Srcport: f.get("sport"),
        Dstport: f.get("dport"),
        Seq: f.get("seq"),
        Ack: f.get("ack"),
        Flags: f.get("tcp_flags"),
    }
    const UDP = {
        SrcPort: f.get("sport"),
        DstPort: f.get("dport"),
    }
    const ICMP = {
        Type: f.get("type"),
        Code: f.get("code"),
    }
    let Network, Transport;

    if (f.get("proto") === "tcp") Transport = TCP;
    else if (f.get("proto") === "udp") Transport = UDP;
    else if (f.get("proto") === "icmp") Transport = ICMP;

    if (Ethernet.Type === "0x0800") Network = IPv4;
    else if (Ethernet.Type === "0x86DD") Network = IPv6;
    else if (Ethernet.Type === "0x0806") {
        Network = ARP;
        Payload = {};
        Transport = {};
    }

    const out = {
        Ethernet,
        Network,
        Transport,
        Payload,
    }
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

// ---------- Template handling ----------
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
            <div class="small text-muted">${t.transport ? t.transport.proto.toUpperCase() : "ARP"}</div>
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

document.querySelector("#loadBuiltin").addEventListener("click", () => renderTemplates(Template.builtinTemplates));

function applyTemplate(t) {
    const form = document.querySelector("#packetForm");
    form.reset();

    const { eth, transport, payload } = t;
    const type = eth.eth_type;

    form.eth_src.value = eth.eth_src;
    form.eth_dst.value = eth.eth_dst;
    form.eth_type.value = eth.eth_type;

    const typeElement = document.querySelector("#networkProtocol");
    typeElement.dispatchEvent(new Event("change"));
    
    if (type === "0x0800") {
        const {ip} = t;
        form.ipv4_src.value = ip.ipv4_src;
        form.ipv4_dst.value = ip.ipv4_dst;
        form.ip_ttl.value = ip.ip_ttl;
        form.ip_id.value = ip.ip_id;
        form.flags.value = ip.flags;
    } else if (type === "0x86DD") {
        const {ipv6} = t;
        form.ipv6_src.value = ipv6.ipv6_src;
        form.ipv6_dst.value = ipv6.ipv6_dst;
    } else if (type === "0x0806") {
        const {arp} = t;
        form.ip_arp_src.value = arp.ip_arp_src;
        form.ip_arp_dst.value = arp.ip_arp_dst;
    }

    if (type === "0x0806") {
        form.payload.value = payload;
        document.querySelector("#tabBuild").classList.remove("d-none");
        document.querySelector("#tabTemplates").classList.add("d-none");
        return;
    }

    const proto = transport.proto;
    form.proto.value = proto;

    const protoElement = document.querySelector("#protoSelect");
    protoElement.dispatchEvent(new Event("change"));
    
    if (proto === "tcp") {
        form.sport.value = transport.sport;
        form.dport.value = transport.dport;
        form.seq.value = transport.seq;
        form.ack.value = transport.ack;
        form.tcp_flags.value = transport.tcp_flags;
    } else if (proto === "udp") {
        form.sport.value = transport.sport;
        form.dport.value = transport.dport;
    } else if (proto === "icmp") {
        form.type.value = transport.type;
        form.code.value = transport.code;
    }

    form.payload.value = payload;
    document.querySelector("#tabBuild").classList.remove("d-none");
    document.querySelector("#tabTemplates").classList.add("d-none");
}

// ---------- Setting handling ----------
document.addEventListener("DOMContentLoaded", async () => {
    const downloadsPathElement = document.querySelector("#defaultFolder");
    const chooseBtn = document.querySelector("#chooseFolder");
  
    let downloadsPath = localStorage.getItem("nettools.downloadsPath");
  
    if (!downloadsPath) {
        downloadsPath = await window.electronAPI.getDownloadsPath();
        localStorage.setItem("nettools.downloadsPath", downloadsPath);
    }
  
    downloadsPathElement.value = downloadsPath;
  
    chooseBtn.addEventListener("click", async () => {
        const folder = await window.electronAPI.chooseFolder();
        if (folder) {
            downloadsPathElement.value = folder;
            localStorage.setItem("nettools.downloadsPath", folder);
        }
    });
});

// ---------- Sniffer handling ----------
function addSniffRow(pkt) {
    const tr = document.createElement("tr");
    const t = new Date(pkt.ts).toLocaleTimeString();
    const src = pkt.obj.ip.src || pkt.obj.ethernet.src;
    const dst = pkt.obj.ip.dst || pkt.obj.ethernet.dst;
    const proto = pkt.obj.transport.proto;
    const payloadSummary = (pkt.obj.payload || "").slice(0, 40);
    tr.innerHTML = `<td>${t}</td><td>${src}</td><td>${dst}</td><td>${proto}</td><td>${payloadSummary}</td>`;
    tr.addEventListener("click", () => {
        document.querySelector("#modalDetail").textContent =
        `Time: ${new Date(pkt.ts).toISOString()}\n\n` +
        JSON.stringify(pkt.obj, null, 2);
        new bootstrap.Modal(document.querySelector("#detailModal")).show();
    });
    document.querySelector("#sniffTable").prepend(tr);
}

//Test
const pkt = {
    ts: Date.now(), // current timestamp
    obj: {
        ip: {
            src: "192.168.1.10",
            dst: "8.8.8.8",
        },
        ethernet: {
            src: "AA:BB:CC:DD:EE:FF",
            dst: "11:22:33:44:55:66",
        },
        transport: {
            proto: "TCP",
        },
        payload: "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
    },
    hex: "474554202f696e6465782e68746d6c20485454502f312e310d0a486f73743a206578616d706c652e636f6d0d0a0d0a"
};
addSniffRow(pkt);
  
document.querySelector("#clearSniff").addEventListener("click", () => {
    document.querySelector("#sniffTable").innerHTML = "";
    packetStore.sent = [];
    packetStore.received = [];
});