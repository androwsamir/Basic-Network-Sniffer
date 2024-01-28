from scapy.all import sniff, Ether, IP, TCP, ARP, UDP, ICMP

def packet_callback(packet):
    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst

        if ARP in packet:
            arp_src_ip = packet[ARP].psrc
            arp_dst_ip = packet[ARP].pdst
            arp_op = packet[ARP].op  # Operation (request or reply)

            print(f"ARP packet from {src_mac} to {dst_mac}")
            print(f"\tARP source IP: {arp_src_ip}")
            print(f"\tARP destination IP: {arp_dst_ip}")
            print(f"\tARP operation: {'Request' if arp_op == 1 else 'Reply'}")

    if Ether in packet and IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if protocol == 1:  # ICMP
            print(f"ICMP Type: {packet[ICMP].type}")
            print(f"ICMP Code: {packet[ICMP].code}")
        elif protocol == 2:  # IGMP
            print(f"IGMP Type: {packet[IGMP].type}")
        elif protocol == 6:  # TCP
            print(f"TCP packet from {src_ip} to {dst_ip}")
            print(f"\tSource Port (TCP): {packet[TCP].sport}")
            print(f"\tDestination Port (TCP): {packet[TCP].dport}")
            print(f"\tTCP Flags: {packet[TCP].flags}")
        elif protocol == 17:  # UDP
            print(f"UDP packet from {src_ip} to {dst_ip}")
            print(f"\tSource Port (UDP): {packet[UDP].sport}")
            print(f"\tDestination Port (UDP): {packet[UDP].dport}")
        elif protocol == 27:  # RDP
            print(f"RDP packet from {src_ip} to {dst_ip}")
        elif protocol == 28:  # RUDP
            print(f"RUDP packet from {src_ip} to {dst_ip}")
        elif protocol == 33:  # DCCP
            print(f"DCCP packet from {src_ip} to {dst_ip}")
        elif protocol == 84:  # ATP
            print(f"ATP packet from {src_ip} to {dst_ip}")
        elif protocol == 88:  # EIGRP
            print(f"EIGRP packet from {src_ip} to {dst_ip}")
        elif protocol == 89:  # OSPF
            print(f"OSPF packet from {src_ip} to {dst_ip}")
        elif protocol == 103:  # PIM
            print(f"PIM packet from {src_ip} to {dst_ip}")
        elif protocol == 121:  # SAP
            print(f"SAP packet from {src_ip} to {dst_ip}")
        elif protocol == 132:  # SCTP
            print(f"SCTP packet from {src_ip} to {dst_ip}")
        elif protocol == 133:  # FCP
            print(f"FCP packet from {src_ip} to {dst_ip}")
        elif protocol == 136:  # SST
            print(f"SST packet from {src_ip} to {dst_ip}")
        elif protocol == 142:  # SPX
            print(f"SPX packet from {src_ip} to {dst_ip}")
        else:
            print(f"unknown protocol ({protocol}) from {src_ip} to {dst_ip}")

if __name__ == '__main__':
    sniff(prn=packet_callback, store=0)
