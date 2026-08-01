from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    print("\n==============================")

    if IP in packet:
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")

        if TCP in packet:
            print("Protocol       : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        elif UDP in packet:
            print("Protocol       : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        else:
            print("Protocol       : Other")

print("Basic Packet Sniffer Started...")
print("Press Ctrl + C to stop.\n")

sniff(prn=process_packet, store=False)
