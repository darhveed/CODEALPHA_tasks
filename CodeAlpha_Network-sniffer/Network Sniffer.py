# Import required Scapy modules
from scapy.all import sniff, IP, TCP, UDP, Raw

# This function analyzes every captured packet
def analyze_packet(packet):

    # Check if the packet contains an IP layer
    if IP in packet:
        print("\n=== New Packet Captured ===")

        # Extract source and destination IP addresses
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")

        # Check if the packet uses TCP protocol
        if TCP in packet:
            print("Protocol: TCP")
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        # Check if the packet uses UDP protocol
        elif UDP in packet:
            print("Protocol: UDP")
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        # Check if packet contains raw payload data
        if Raw in packet:
            # Display only the first 40 bytes for safety
            payload = packet[Raw].load[:40]
            print(f"Payload (first 40 bytes): {payload}")

# Notify user that packet capture has started
print("Starting packet capture...")

# Start sniffing network traffic
# prn → function called for each packet
# store=False → do not store packets in memory
sniff(prn=analyze_packet, store=False, count=50)
