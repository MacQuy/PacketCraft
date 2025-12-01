window.onscroll = function () {
    let texts = document.querySelectorAll(".description");

    texts.forEach(function (text) {
        let rect = text.getBoundingClientRect();
        if (rect.top < window.innerHeight && rect.bottom > 0) {
            text.classList.add("show");
        } else {
            text.classList.remove("show");
        }
    });
};

const sortBtn = document.getElementById("sort-btn");
const clearBtn = document.getElementById("clear-btn");
const resultsDiv = document.getElementById("results-div");
const userInput = document.getElementById("user-input");

sortBtn.addEventListener("click", sort);
clearBtn.addEventListener("click", clear);

async function sort() {
    const raw = userInput.value.trim();
    if (!raw) {
        resultsDiv.textContent = "Please enter numbers.";
        return;
    }
    const items = raw.split(/[\s,]+/).map(Number);

    try {
        const response = await fetch("http://127.0.0.1:5000/sort", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ items })
        });

        const data = await response.json();

        if (response.ok) {
            resultsDiv.textContent = "Sorted: " + data.sorted.join(", ");
        } else {
            resultsDiv.textContent = "Error: " + (data.error || "Unknown error");
        }
    } catch (err) {
        resultsDiv.textContent = "Request failed: " + err;
    }
}

async function buildPacket() {
    const data = {
        src: document.getElementById("src").value,
        dst: document.getElementById("dst").value,
        protocol: document.getElementById("protocol").value,
        sport: document.getElementById("sport").value,
        dport: document.getElementById("dport").value,
        payload: document.getElementById("payload").value
    };

    const res = await fetch("http://127.0.0.1:5000/packet/build", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(data)
    });

    const json = await res.json();
    document.getElementById("packetResult").innerText = JSON.stringify(json, null, 2);
}

async function sendPacket() {
    const data = {
        src: document.getElementById("src").value,
        dst: document.getElementById("dst").value,
        protocol: document.getElementById("protocol").value,
        sport: document.getElementById("sport").value,
        dport: document.getElementById("dport").value,
        payload: document.getElementById("payload").value
    };

    const res = await fetch("http://127.0.0.1:5000/packet/send", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(data)
    });

    const json = await res.json();
    document.getElementById("packetResult").innerText = JSON.stringify(json, null, 2);
}

function clear() {
    userInput.value = "";
    resultsDiv.innerText = "";
}