from scapy.all import sniff, IP, TCP, UDP, ICMP
import datetime

# Function to process captured packets
def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Determine protocol type
        if protocol == 6:
            proto_name = "TCP"
        elif protocol == 17:
            proto_name = "UDP"
        elif protocol == 1:
            proto_name = "ICMP"
        else:
            proto_name = "OTHER"

        print(f"[{timestamp}] {proto_name} Packet: {src_ip} ➝ {dst_ip}")

        # Save to log file
        with open("sniffer_log.txt", "a") as log:
            log.write(f"[{timestamp}] {proto_name} Packet: {src_ip} ➝ {dst_ip}\n")

# Start packet sniffing
def start_sniffing(interface="eth0"):
    print(f"\n🔍 Packet Sniffer Running on {interface}... Press Ctrl+C to stop.\n")
    sniff(prn=process_packet, store=False)  # Captures packets and sends to process_packet()

# Run the sniffer
if __name__ == "__main__":
    start_sniffing()
