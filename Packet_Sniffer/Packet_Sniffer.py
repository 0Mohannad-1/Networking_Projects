from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def bpf_filter_syntax_help():
    print("\n=== BPF Filter Syntax Examples ===")
    print("Filter by protocol:")
    print("  tcp              - Capture only TCP packets")
    print("  udp              - Capture only UDP packets")
    print("  icmp             - Capture only ICMP packets (ping)")
    print("\nFilter by port:")
    print("  port <port-number>          - Capture packets on a specific port")
    print("  tcp port <port-number>      - Capture TCP packets on a specific port")
    print("  udp port <port-number>      - Capture UDP packets on a specific port")
    print("\nFilter by host IP:")
    print("  host <ip-address>           - Packets to or from a specific IP")
    print("  src host <ip-address>       - Packets coming from a specific IP")
    print("  dst host <ip-address>       - Packets going to a specific IP")
    print("\nCombine filters:")
    print("  <filter1> and <filter2>     - Both filters must match")
    print("  <filter1> or <filter2>      - Either filter can match")
    print("  Use parentheses () to group conditions")
    print("\nNegate filters:")
    print("  not <filter>                - Negate a filter condition")
    print("\nLeave empty to capture all traffic (no filter).")
    print("=================================\n")

def select_packet_count():
    while True:
        number_of_packets = input("Enter the number of packets to sniff (Leave blank for unlimited): ").strip()
        if number_of_packets == "":
            return 0
        try:
            return int(number_of_packets)
        except ValueError:
            print("Please enter a valid integer.")

def select_output_level():
    while True:
        output_level = input("Choose output detail level ('detailed' or 'summary'): ").strip().lower()
        if output_level in ["detailed", "summary"]:
            return output_level
        print("Invalid input. Try again.")

def packet_info(pkt):
    print("\n=== Packet ===")
    
    if pkt.haslayer(IP):
        print(f"Source IP: {pkt[IP].src}")
        print(f"Destination IP: {pkt[IP].dst}")
    
        if pkt.haslayer(TCP):
            print(f"Source Port: {pkt[TCP].sport}")
            print(f"Destination Port: {pkt[TCP].dport}")

        elif pkt.haslayer(UDP):
            print(f"Source Port: {pkt[UDP].sport}")
            print(f"Destination Port: {pkt[UDP].dport}")
        
        elif pkt.haslayer(ICMP):
            print(f"Type: {pkt.type}")
            print(f"Code: {pkt.code}")

    payload = ""
    if pkt.haslayer(Raw):
        raw_bytes = pkt[Raw].load
        try:
            payload = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            payload = str(raw_bytes)

    print(f"The Data: {payload[:100]}")  # Display first 100 characters of payload

    if output_level == "detailed":
        pkt.show()
    else:
        print(pkt.summary())

# Main program
number_of_packets = select_packet_count()
output_level = select_output_level()

while True:
    bpf_filter = input("Enter a BPF filter (or press Enter for no filter): ").strip()

    try:
        # Quick test sniff to validate the filter
        sniff(count=1, timeout=2, filter=bpf_filter if bpf_filter else None, prn=lambda x: None)

        # If filter is valid, start sniffing
        print("Starting packet capture... Press Ctrl+C to stop.")
        
        sniff(
            count=number_of_packets if number_of_packets > 0 else 0,
            filter=bpf_filter if bpf_filter else None,
            prn=packet_info
        )
        
        break  # Only break if sniff finishes naturally (limited packet count)

    except Exception as e:
        print(f"Error: {e}")
        print("Please enter a valid BPF filter.")