# pcap_to_log.py
from scapy.all import rdpcap, IP, TCP, UDP

def pcap_to_text(pcap_file, output_file):
    print(f"Reading {pcap_file}...")
    packets = rdpcap(pcap_file)
    
    lines = []
    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto = pkt[IP].proto
            
            # Extract details based on protocol
            if TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                flags = pkt[TCP].flags
                lines.append(f"TCP {src_ip}:{sport} -> {dst_ip}:{dport} [Flags: {flags}]")
            elif UDP in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                lines.append(f"UDP {src_ip}:{sport} -> {dst_ip}:{dport}")
            else:
                lines.append(f"IP {src_ip} -> {dst_ip} (Proto: {proto})")
                
    with open(output_file, 'w') as f:
        f.write("\n".join(lines))
    print(f"Saved {len(lines)} log lines to {output_file}")

if __name__ == "__main__":
    # Change 'network_capture.pcap' to your actual file name
    pcap_to_text("network_capture.pcap", "wireshark_logs.txt")