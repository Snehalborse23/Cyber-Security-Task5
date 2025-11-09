# Task 05 - Network Packet Analyzer (Educational Use Only)
# Author: Snehal Borse
# Description: A simple network packet sniffer for learning and cybersecurity awareness.

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    """Function to process each captured packet"""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        # Identify protocol name
        if proto == 6:
            protocol_name = "TCP"
        elif proto == 17:
            protocol_name = "UDP"
        elif proto == 1:
            protocol_name = "ICMP"
        else:
            protocol_name = f"Other({proto})"

        print("=" * 60)
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol_name}")

        # Optional payload display
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload)
            if payload:
                print(f"Payload (first 100 bytes): {payload[:100]}")
        print("=" * 60)

print("🕵️‍♂️ Starting Network Packet Analyzer...")
print("Press Ctrl+C to stop capturing.\n")

# Capture 20 packets (change count as needed)
sniff(filter="ip", prn=packet_callback, count=20)
