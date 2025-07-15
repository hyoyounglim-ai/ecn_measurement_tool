from scapy.all import IP, UDP, send, sniff

# dst_ip = "3.106.225.6"  # 예: "192.0.2.1"
dst_ip = "49.50.129.152"  # 예: "192.0.2.1"
# sudo python3 ttl_ecn_probe.py 3.106.225.6 --port 9999 --ttl 10 --tos 0x02

## 49.50.129.152
dst_port = 9999
src_port = 53000
tos = 0x3  # ECN: ECT(0) (0b10)

pkt = IP(dst=dst_ip, tos=tos) / UDP(sport=src_port, dport=dst_port) / b"ping"
print(f"[Client] Sending ECN-marked packet with TOS={hex(tos)} to {dst_ip}:{dst_port}")
send(pkt)

# 수신 응답 감시
def handle_response(pkt):
    if IP in pkt and UDP in pkt and pkt[UDP].sport == dst_port:
        ip_layer = pkt[IP]
        tos = ip_layer.tos
        ecn = tos & 0b11
        ecn_str = {
            0b00: "Not-ECT",
            0b01: "ECT(1)",
            0b10: "ECT(0)",
            0b11: "CE"
        }.get(ecn, "Unknown")
        print(f"[Client] Received reply from {ip_layer.src}, TOS={hex(tos)}, ECN={ecn_str}")

print("[Client] Waiting for response...")
sniff(filter=f"udp and port {src_port}", prn=handle_response, timeout=3)
