import * as Helper from "./helperFunction.js";
import * as Validation from "./validation.js";

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

// ---------- Build Packet ----------
function renderLayered(obj) {
    let s = "";
    s += `Ethernet:\n  Src: ${obj.ethernet.src}\n  Dst: ${obj.ethernet.dst}\n  Type: ${obj.ethernet.type}\n\n`;
    s += `IP (v${obj.ip.ver}):\n  Src: ${obj.ip.src}\n  Dst: ${obj.ip.dst}\n  TTL: ${obj.ip.ttl}\n\n`;
    s += `Transport (${obj.transport.proto}):\n  SrcPort: ${obj.transport.sport}\n  DstPort: ${obj.transport.dport}\n  Flags: ${obj.transport.flags}\n\n`;
    s += `Payload (${obj.payload.length} bytes):\n  ${obj.payload}\n`;
    document.querySelector("#layerPreview").textContent = s;
}
  
function renderHex(obj) {
    const parts = [];
    parts.push(`ETH_SRC:${obj.ethernet.src}`);
    parts.push(`ETH_DST:${obj.ethernet.dst}`);
    parts.push(`IP_SRC:${obj.ip.src}`);
    parts.push(`IP_DST:${obj.ip.dst}`);
    parts.push(`PROTO:${obj.transport.proto}`);
    parts.push(`PAYLOAD:${obj.payload}`);
    const joined = parts.join("|");
    document.querySelector("#hexPreview").textContent = Helper.toHex(joined);
    return Helper.toHex(joined);
}
  
document.querySelector("#btnBuild").addEventListener("click", () => {
    const obj = gatherForm();
    renderLayered(obj);
    renderHex(obj);
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
        JSON.stringify(pkt.obj, null, 2) +
        "\n\nHEX:\n" +
        pkt.hex;
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

// ---------- Template handling ----------
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