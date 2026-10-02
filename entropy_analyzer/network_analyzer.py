from scapy.all import rdpcap, TCP, UDP, Raw
from typing import List, Dict
import logging

from .core import calculate_shannon_entropy

def analyze_pcap(filepath: str, threshold: float = 7.9) -> List[Dict]:
    """
    Analyzes a PCAP file and calculates the entropy of packet payloads.
    Returns a list of dictionaries containing packet info and entropy scores.
    """
    results = []
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        logging.error(f"Failed to read PCAP file: {e}")
        return results

    for i, pkt in enumerate(packets):
        # We are only interested in packets that have a Raw payload
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            
            # Skip very small payloads as their entropy might be skewed
            if len(payload) < 16:
                continue
                
            entropy = calculate_shannon_entropy(payload)
            
            # Determine protocol
            protocol = "Unknown"
            if pkt.haslayer(TCP):
                protocol = f"TCP ({pkt[TCP].sport} -> {pkt[TCP].dport})"
            elif pkt.haslayer(UDP):
                protocol = f"UDP ({pkt[UDP].sport} -> {pkt[UDP].dport})"
                
            is_malicious = entropy >= threshold
            
            results.append({
                "packet_id": i + 1,
                "protocol": protocol,
                "payload_size": len(payload),
                "entropy": round(entropy, 4),
                "is_malicious": is_malicious
            })
            
    return results
