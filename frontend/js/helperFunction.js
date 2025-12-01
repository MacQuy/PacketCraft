export const qs = (s, root = document) => root.querySelector(s);
export const qsa = (s, root = document) => [...root.querySelectorAll(s)];

export const toHex = (str) => 
    Array.from(new TextEncoder().encode(str))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(" ");

export const hexToBytes = (hex) =>
    new Uint8Array(
        hex
        .split(/\s+/)
        .filter(Boolean)
        .map((h) => parseInt(h, 16))
);

export const nowTs = () => Math.floor(Date.now() / 1000);
