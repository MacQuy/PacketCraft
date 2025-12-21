import * as Helper from "./helperFunction.js"
import * as Validation from "./validation.js";
import * as Template from "./templates.js";

const packetStore = { sent: [], received: [] };

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
function formatObject(obj, indent = 0) {
    let result = "";
    const padding = "  ".repeat(indent);

    for (const [key, value] of Object.entries(obj)) {
        if (value === undefined || value === null || value === "") continue;

        const formattedKey = key.charAt(0).toUpperCase() + key.slice(1);

        if (typeof value === "object" && !Array.isArray(value)) {
            if (Object.keys(value).length === 0) continue;

            result += `${padding}${formattedKey}:\n`;
            result += formatObject(value, indent + 1);
            result += `${padding}\n`;
        } else {
            result += `${padding}${formattedKey}: ${value}\n`;
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

    const out = {
        eth: Helper.removeNulls({
            eth_src: f.get("eth_src"),
            eth_dst: f.get("eth_dst"),
            eth_type: f.get("eth_type")
        }),
        transport: Helper.removeNulls({
            proto: Helper.clean(f.get("proto")),
            sport: Helper.clean(f.get("sport")),
            dport: Helper.clean(f.get("dport")),
            seq: Helper.clean(f.get("seq")),
            ack: Helper.clean(f.get("ack")),
            tcp_flags: Helper.clean(f.get("tcp_flags")),
            type: Helper.clean(f.get("type")),
            code: Helper.clean(f.get("code"))
        }),
        payload: Helper.clean(f.get("payload"))
    };

    if (f.get("eth_type") === "0x0800") {
        out.ip = Helper.removeNulls({
            ipv4_src: Helper.clean(f.get("ipv4_src")),
            ipv4_dst: Helper.clean(f.get("ipv4_dst")),
            ip_ttl: Helper.clean(f.get("ipv4_ttl")),
            ip_id: Helper.clean(f.get("ip_id")),
            flags: Helper.clean(f.get("flags"))
        });
    }

    if (f.get("eth_type") === "0x86DD") {
        out.ipv6 = Helper.removeNulls({
            ipv6_src: Helper.clean(f.get("ipv6_src")),
            ipv6_dst: Helper.clean(f.get("ipv6_dst"))
        });
    }

    if (f.get("eth_type") === "0x0806") {
        out.arp = Helper.removeNulls({
            op: Helper.clean(f.get("op")),
            ip_arp_src: Helper.clean(f.get("ip_arp_src")),
            ip_arp_dst: Helper.clean(f.get("ip_arp_dst"))
        });
    }

    return out;
}

function getInterfaces() {
    fetch("http://localhost:5000/interfaces")
    .then(res => res.json())
    .then(data => {
        const select = document.getElementById("ifaceSelect");
        select.innerHTML = "";

        data.interfaces.forEach(iface => {
            let opt = document.createElement("option");
            opt.value = iface;
            opt.textContent = iface;
            select.appendChild(opt);
        });
    });
}
getInterfaces();

function sendPacket() {
    fetch("http://localhost:5000/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            interface: document.getElementById("ifaceSelect").value,
            packet: gatherForm()
        })
    })
    .then(r => r.json())
    .then(data => {
        console.log(data);

        const pkt = {
            ts: Date.now(),
            obj: data.response_summary
        };

        addSniffRow(pkt);
    });
}
document.querySelector("#btnSend").addEventListener("click", sendPacket)

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
    document.querySelector('a[data-target="#tabBuild"]').classList.add("active");
    document.querySelector("#tabTemplates").classList.add("d-none");
    document.querySelector('a[data-target="#tabTemplates"]').classList.remove("active");
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
    const src = pkt.obj.ip.ipv4_src || pkt.obj.eth.eth_src;
    const dst = pkt.obj.ip.ipv4_dst || pkt.obj.eth.eth_dst;
    const proto = (["icmp", "tcp", "udp"].find(k => k in pkt.obj)).toUpperCase() || null;
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
  
document.querySelector("#clearSniff").addEventListener("click", () => {
    document.querySelector("#sniffTable").innerHTML = "";
    packetStore.sent = [];
    packetStore.received = [];
    fetch("http://localhost:5000/clear-logs", { method: "POST" }).catch(() => {});
});

// ---------- Tools: Traceroute ----------
const traceOutput = document.querySelector("#traceOut");

function formatTraceroute(hops) {
    const ttlWidth = Math.max(3, ...hops.map((hop) => String(hop.ttl).length));
    const ipWidth = Math.max(2, ...hops.map((hop) => String(hop.ip || "").length));
    const rttValues = hops.map((hop) => (hop.rtt_ms === null ? "--" : `${hop.rtt_ms} ms`));
    const rttWidth = Math.max(3, ...rttValues.map((val) => val.length));

    const rows = hops.map((hop, idx) => {
        const ttl = String(hop.ttl).padEnd(ttlWidth, " ");
        const ip = String(hop.ip || "").padEnd(ipWidth, " ");
        const rtt = rttValues[idx].padEnd(rttWidth, " ");
        const status = String(hop.status || "");
        return `${ttl}  ${ip}  ${rtt}  ${status}`;
    });

    const header = [
        "TTL".padEnd(ttlWidth, " "),
        "IP".padEnd(ipWidth, " "),
        "RTT".padEnd(rttWidth, " "),
        "Status"
    ].join("  ");

    return `${header}\n${rows.join("\n")}`;
}

const startTraceButton = document.querySelector("#startTrace");

startTraceButton.addEventListener("click", () => {
    const host = document.querySelector("#trHost").value.trim();
    if (!host) {
        traceOutput.textContent = "Please enter a host.";
        return;
    }

    traceOutput.textContent = `Tracing route to ${host}...\n`;
    startTraceButton.disabled = true;

    fetch("http://localhost:5000/traceroute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ host })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status !== "success") {
            traceOutput.textContent = `Error: ${data.message || "Traceroute failed."}`;
            return;
        }

        const header = `Target: ${data.target} (${data.target_ip})\n`;
        traceOutput.textContent = header + formatTraceroute(data.hops);
    })
    .catch(err => {
        traceOutput.textContent = `Error: ${err.message || "Traceroute failed."}`;
    })
    .finally(() => {
        startTraceButton.disabled = false;
    });
});

// ---------- Tools: Port Scan ----------
const scanResultBody = document.querySelector("#scanResult");
const startScanButton = document.querySelector("#startScan");

function renderScanResults(results, { hideClosed } = {}) {
    scanResultBody.innerHTML = "";
    results
    .filter((entry) => !hideClosed || entry.state !== "closed")
    .forEach((entry) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `<td>${entry.port}</td><td>${entry.state}</td>`;
        scanResultBody.appendChild(tr);
    });
}

startScanButton.addEventListener("click", () => {
    const host = document.querySelector("#scanHost").value.trim();
    const ports = document.querySelector("#scanPorts").value.trim();
    scanResultBody.innerHTML = "";

    if (!host || !ports) {
        scanResultBody.innerHTML = `<tr><td colspan="2">Please enter host and ports.</td></tr>`;
        return;
    }
    const hideClosed = ports.includes("-");
    startScanButton.disabled = true;

    fetch("http://localhost:5000/port-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ host, ports })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status !== "success") {
            scanResultBody.innerHTML = `<tr><td colspan="2">Error: ${data.message || "Scan failed."}</td></tr>`;
            return;
        }
        renderScanResults(data.results, { hideClosed });
    })
    .catch(err => {
        scanResultBody.innerHTML = `<tr><td colspan="2">Error: ${err.message || "Scan failed."}</td></tr>`;
    })
    .finally(() => {
        startScanButton.disabled = false;
    });
});

// ---------- Tools: Batch Send / Stress Test ----------
const startBatchButton = document.querySelector("#startBatch");
const stopBatchButton = document.querySelector("#stopBatch");
const batchCountInput = document.querySelector("#batchCount");
const batchRateInput = document.querySelector("#batchRate");
const statSentEl = document.querySelector("#statSent");
const statRecvEl = document.querySelector("#statRecv");
const statLossEl = document.querySelector("#statLoss");

let batchRunning = false;
let batchAbort = false;

function updateBatchStats(sent, received) {
    const loss = sent > 0 ? Math.round(((sent - received) / sent) * 100) : 0;
    statSentEl.textContent = String(sent);
    statRecvEl.textContent = String(received);
    statLossEl.textContent = String(loss);
}

async function sendBatchPacket() {
    const iface = document.getElementById("ifaceSelect").value;
    if (!iface) {
        throw new Error("Interface required");
    }
    const response = await fetch("http://localhost:5000/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            interface: iface,
            packet: gatherForm()
        })
    });
    return response.json();
}

async function runBatchSend() {
    const count = parseInt(batchCountInput.value, 10);
    const rate = parseFloat(batchRateInput.value);
    if (!Number.isFinite(count) || count <= 0) {
        return;
    }
    if (!Number.isFinite(rate) || rate <= 0) {
        return;
    }

    batchRunning = true;
    batchAbort = false;
    startBatchButton.disabled = true;
    stopBatchButton.disabled = false;
    updateBatchStats(0, 0);

    const intervalMs = Math.max(1, Math.round(1000 / rate));
    let sent = 0;
    let received = 0;

    try {
        for (let i = 0; i < count; i += 1) {
            if (batchAbort) {
                break;
            }
            sent += 1;
            try {
                const data = await sendBatchPacket();
                if (data && data.status === "success") {
                    if (data.response_summary) {
                        received += 1;
                        addSniffRow({ ts: Date.now(), obj: data.response_summary });
                    }
                }
            } catch (err) {
                console.error(err);
            }
            updateBatchStats(sent, received);
            await new Promise((resolve) => setTimeout(resolve, intervalMs));
        }
    } finally {
        batchRunning = false;
        startBatchButton.disabled = false;
        stopBatchButton.disabled = true;
    }
}

startBatchButton.addEventListener("click", () => {
    if (batchRunning) {
        return;
    }
    runBatchSend();
});

stopBatchButton.addEventListener("click", () => {
    if (!batchRunning) {
        return;
    }
    batchAbort = true;
    stopBatchButton.disabled = true;
});

// ---------- Sniffer: Export PCAP ----------
const exportPcapButton = document.querySelector("#exportPcap");

exportPcapButton.addEventListener("click", () => {
    const folder = localStorage.getItem("nettools.downloadsPath");
    if (!folder) {
        return;
    }
    const filename = `packetcraft_${Date.now()}.pcap`;
    exportPcapButton.disabled = true;
    fetch("http://localhost:5000/export-pcap", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ folder, filename })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status !== "success") {
            console.error(data.message || "Export failed.");
        }
    })
    .catch(err => {
        console.error(err);
    })
    .finally(() => {
        exportPcapButton.disabled = false;
    });
});

renderTemplates(Template.builtinTemplates)