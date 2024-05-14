import scapy.all as scapy

def packet_sniffer(packet):
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            print(f"Source IP: {source_ip}  Destination IP: {destination_ip}  Protocol: {protocol}  Payload: {payload}")
        else:
            print(f"Source IP: {source_ip}  Destination IP: {destination_ip}  Protocol: {protocol}")

def main():
    print("Packet Sniffer started. Press 'Ctrl+C' to stop.")
    try:
        scapy.sniff(iface="eth0", prn=packet_sniffer, store=False)
    except KeyboardInterrupt:
        print("Packet Sniffer stopped.")

if __name__ == "__main__":
    main()