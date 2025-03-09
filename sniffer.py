from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    """
    Callback function to process each captured packet.

    :param packet: The captured packet.
    """
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")

        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP")
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol: UDP")
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
        
        if packet.haslayer('Raw'):
            payload = packet['Raw'].load
            print(f"Payload: {payload.decode(errors='ignore')}")
        
        print("-" * 50)

def main():
    """
    Main function to start the packet sniffer.
    """
    print("Starting packet sniffer. Press CTRL+C to stop.")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()