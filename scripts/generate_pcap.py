import sys
import os
import random
from scapy.all import IP, TCP, Raw, wrpcap

def generate_mock_pcap(filepath: str):
    """Generates a PCAP file with mixed regular traffic and encrypted (high entropy) payloads."""
    packets = []
    
    # 1. Generate Legitimate HTTP-like Traffic (Low Entropy)
    for _ in range(5):
        payload = b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n" + b"Padding "*20
        pkt = IP(dst="192.168.1.100")/TCP(dport=80, sport=random.randint(1024, 65535))/Raw(load=payload)
        packets.append(pkt)
        
    # 2. Generate Simulated Malicious Encrypted C2 Traffic (High Entropy)
    for _ in range(3):
        # High entropy payload mimicking AES/TLS
        encrypted_payload = os.urandom(500) 
        pkt = IP(dst="10.0.0.50")/TCP(dport=443, sport=random.randint(1024, 65535))/Raw(load=encrypted_payload)
        packets.append(pkt)

    # 3. Generate some more Legitimate Traffic
    for _ in range(2):
        payload = b"Plaintext data being sent over the network to simulate regular activity. " * 5
        pkt = IP(dst="192.168.1.150")/TCP(dport=8080, sport=random.randint(1024, 65535))/Raw(load=payload)
        packets.append(pkt)
        
    wrpcap(filepath, packets)
    print(f"Generated mock PCAP file: {filepath} with {len(packets)} packets.")

if __name__ == "__main__":
    generate_mock_pcap("sample_traffic.pcap")
