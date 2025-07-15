from scapy.all import IP, UDP, send, sr1
import argparse
import time

def ecn_probe(dest_ip, dport=9999, max_ttl=30, tos=0x01):  # 0x02 = ECT(0)
    print(f"[+] Starting ECN TTL probe to {dest_ip}, TOS={hex(tos)}, max TTL={max_ttl}")

    for ttl in range(1, max_ttl + 1):
        ip = IP(dst=dest_ip, ttl=ttl, tos=tos)
        udp = UDP(sport=53000 + ttl, dport=dport)
        pkt = ip / udp / b"ecn_probe"

        print(f"[→] Sending TTL={ttl} packet with ECN={hex(tos)}")
        send(pkt, verbose=0)
        time.sleep(0.3)  # 조절 가능

    print("[+] Probe complete. Now check destination for ECN preservation.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TTL-based ECN probe tool")
    parser.add_argument("dst", help="Destination IP")
    parser.add_argument("--port", type=int, default=9999, help="UDP target port")
    parser.add_argument("--ttl", type=int, default=15, help="Maximum TTL")
    parser.add_argument("--tos", type=lambda x: int(x, 0), default=0x02, help="TOS value (ECN: 0x02=ECT(0))")

    args = parser.parse_args()
    ecn_probe(args.dst, args.port, args.ttl, args.tos)
