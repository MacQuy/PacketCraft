export const builtinTemplates = [
    // ===============================
    // ICMP / PING
    // ===============================
    {
        name: "Ping (ICMP Echo Request)",
        eth: {
            eth_src: "00:0c:29:aa:bb:cc",
            eth_dst: "ff:ff:ff:ff:ff:ff",
            eth_type: "0x0800"
        },
        ip: {
            ipv4_src: "192.168.1.100",
            ipv4_dst: "192.168.1.1",
            ip_ttl: "64",
            ip_id: "1",
            flags: ""
        },
        transport: {
            proto: "icmp",
            type: "8",
            code: "0"
        },
        payload: "Ping Test"
    },
    {
        name: "ICMP Echo Reply",
        eth: {
            eth_src: "00:0c:29:11:22:33",
            eth_dst: "00:0c:29:aa:bb:cc",
            eth_type: "0x0800"
        },
        ip: {
            ipv4_src: "192.168.1.1",
            ipv4_dst: "192.168.1.100",
            ip_ttl: "64",
            ip_id: "2",
            flags: ""
        },
        transport: {
            proto: "icmp",
            type: "0",
            code: "0"
        },
        payload: "Pong!"
    },
  
    // ===============================
    // ARP
    // ===============================
    {
        name: "ARP Request",
        eth: {
            eth_src: "00:0c:29:aa:bb:cc",
            eth_dst: "ff:ff:ff:ff:ff:ff",
            eth_type: "0x0806"
        },
        arp: {
            op: "1",
            ip_arp_src: "192.168.1.100",
            ip_arp_dst: "192.168.1.1"
        },
        payload: ""
    },
    {
        name: "ARP Reply",
        eth: {
            eth_src: "00:0c:29:11:22:33",
            eth_dst: "00:0c:29:aa:bb:cc",
            eth_type: "0x0806"
        },
        arp: {
            op: "2",
            ip_arp_src: "192.168.1.1",
            ip_arp_dst: "192.168.1.100"
        },
        payload: ""
    },
  
    // ===============================
    // TCP
    // ===============================
    {
        name: "TCP SYN",
        eth: {
            eth_src: "00:0c:29:aa:bb:cc",
            eth_dst: "00:0c:29:11:22:33",
            eth_type: "0x0800"
        },
        ip: {
            ipv4_src: "192.168.1.100",
            ipv4_dst: "192.168.1.1",
            ip_ttl: "64",
            ip_id: "101",
            flags: ""
        },
        transport: {
            proto: "tcp",
            sport: "40000",
            dport: "80",
            seq: "0",
            ack: "",
            tcp_flags: "S"
        },
        payload: ""
    },
    {
        name: "TCP SYN-ACK",
        eth: {
            eth_src: "00:0c:29:11:22:33",
            eth_dst: "00:0c:29:aa:bb:cc",
            eth_type: "0x0800"
        },
        ip: {
            ipv4_src: "192.168.1.1",
            ipv4_dst: "192.168.1.100",
            ip_ttl: "64",
            ip_id: "102",
            flags: ""
        },
        transport: {
            proto: "tcp",
            sport: "80",
            dport: "40000",
            seq: "1",
            ack: "1",
            tcp_flags: "SA"
        },
        payload: ""
    },
    {
        name: "TCP ACK",
        eth: {
            eth_src: "00:0c:29:aa:bb:cc",
            eth_dst: "00:0c:29:11:22:33",
            eth_type: "0x0800"
        },
        ip: {
            ipv4_src: "192.168.1.100",
            ipv4_dst: "192.168.1.1",
            ip_ttl: "64",
            ip_id: "103",
            flags: ""
        },
        transport: {
            proto: "tcp",
            sport: "40000",
            dport: "80",
            seq: "1",
            ack: "2",
            tcp_flags: "A"
        },
        payload: ""
    },
    {
        name: "HTTP GET Request",
        eth: {
            eth_src: "00:0c:29:aa:bb:cc",
            eth_dst: "00:0c:29:11:22:33",
            eth_type: "0x0800"
        },
        ip: {
            ipv4_src: "192.168.1.100",
            ipv4_dst: "93.184.216.34",
            ip_ttl: "64",
            ip_id: "104",
            flags: ""
        },
        transport: {
            proto: "tcp",
            sport: "40001",
            dport: "80",
            seq: "1",
            ack: "1",
            tcp_flags: "PA"
        },
        payload: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    },
    {
        name: "HTTP Response (200 OK)",
        eth: {
            eth_src: "00:0c:29:11:22:33",
            eth_dst: "00:0c:29:aa:bb:cc",
            eth_type: "0x0800"
        },
        ip: {
            ipv4_src: "93.184.216.34",
            ipv4_dst: "192.168.1.100",
            ip_ttl: "64",
            ip_id: "105",
            flags: ""
        },
        transport: {
            proto: "tcp",
            sport: "80",
            dport: "40001",
            seq: "2",
            ack: "2",
            tcp_flags: "PA"
        },
        payload: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Hello</body></html>"
    },
  
    // ===============================
    // UDP
    // ===============================
    {
        name: "UDP DNS Query",
        eth: {
            eth_src: "00:0c:29:aa:bb:cc",
            eth_dst: "00:0c:29:11:22:33",
            eth_type: "0x0800"
        },
        ip: {
            ipv4_src: "192.168.1.100",
            ipv4_dst: "8.8.8.8",
            ip_ttl: "64",
            ip_id: "300",
            flags: ""
        },
        transport: {
            proto: "udp",
            sport: "50500",
            dport: "53"
        },
        payload: "DNS Query for example.com"
    },
    {
        name: "UDP Syslog Message",
        eth: {
            eth_src: "00:0c:29:aa:bb:cc",
            eth_dst: "00:0c:29:11:22:33",
            eth_type: "0x0800"
        },
        ip: {
            ipv4_src: "192.168.1.100",
            ipv4_dst: "192.168.1.10",
            ip_ttl: "64",
            ip_id: "301",
            flags: ""
        },
        transport: {
            proto: "udp",
            sport: "514",
            dport: "514"
        },
        payload: "<34>Nov  7 12:00:00 myhost app: System log message"
    },
    {
        name: "UDP DHCP Discover",
        eth: {
            eth_src: "ff:ff:ff:ff:ff:ff",
            eth_dst: "ff:ff:ff:ff:ff:ff",
            eth_type: "0x0800"
        },
        ip: {
            ipv4_src: "0.0.0.0",
            ipv4_dst: "255.255.255.255",
            ip_ttl: "128",
            ip_id: "400",
            flags: ""
        },
        transport: {
            proto: "udp",
            sport: "68",
            dport: "67"
        },
        payload: "DHCPDISCOVER"
    },
  
    // ===============================
    // IPv6
    // ===============================
    {
        name: "IPv6 Ping (ICMPv6 Echo Request)",
        eth: {
            eth_src: "00:0c:29:aa:bb:cc",
            eth_dst: "33:33:00:00:00:01",
            eth_type: "0x86DD"
        },
        ipv6: {
            ipv6_src: "fe80::1",
            ipv6_dst: "fe80::2"
        },
        transport: {
            proto: "icmp",
            type: "128",
            code: "0"
        },
        payload: "IPv6 ping"
    },
    {
        name: "IPv6 Neighbor Solicitation",
        eth: {
            eth_src: "00:0c:29:aa:bb:cc",
            eth_dst: "33:33:ff:11:22:33",
            eth_type: "0x86DD"
        },
        ipv6: {
            ipv6_src: "fe80::1",
            ipv6_dst: "ff02::1:ff11:2233"
        },
        transport: {
            proto: "icmp",
            type: "135",
            code: "0"
        },
        payload: "Neighbor Solicitation"
    },
    {
        name: "IPv6 Neighbor Advertisement",
        eth: {
            eth_src: "00:0c:29:11:22:33",
            eth_dst: "33:33:00:00:00:01",
            eth_type: "0x86DD"
        },
        ipv6: {
            ipv6_src: "fe80::2",
            ipv6_dst: "fe80::1"
        },
        transport: {
            proto: "icmp",
            type: "136",
            code: "0"
        },
        payload: "Neighbor Advertisement"
    }
];