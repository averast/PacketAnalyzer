#!/usr/bin/env python3
from scapy.all import *
import struct
import os
import sys
import random
import time

L_Endian = "<"
B_Endian = ">"
s = ' ' * 3
send_pack = False

# Usage information
if len(sys.argv) == 2:
    file_name = sys.argv[1]
elif sys.argv[1] == '-s':
    file_name = sys.argv[2]
    send_pack = True
else:
    print("Incorrect usage or no configuration file")
    sys.exit(1)
    
# Open cfg file and read in values
cfg_list = []
with open(file_name, "r") as g:
    for line in g:
        line = line.rstrip()
        cfg_list.append(line)

# cfg_list assignments
pcap_file = cfg_list[0]
original_victim_mac = cfg_list[2]
original_attacker_mac = cfg_list[5]
replay_victim_ip = cfg_list[7]
replay_victim_mac = cfg_list[8]
replay_victim_port = cfg_list[9]
replay_attacker_ip = cfg_list[10]
replay_attacker_mac = cfg_list[11]
replay_attacker_port = cfg_list[12]
interface = cfg_list[13]
timing = cfg_list[14]

# Open pcap file in binary mode to read values 
with open(pcap_file, "rb") as f:
    f_bytes = f.read()
if f_bytes[:2] == b"\xa1\xb2":
    endianness = B_Endian
elif f_bytes[:2] == b"\xd4\xc3":
    endianness = L_Endian

# Pcap file header information
pcap_headers = struct.unpack(endianness + "IHHIIII", f_bytes[:24])
print("PCAP_MAGIC")
print("Version major number =", pcap_headers[1])
print("Version minor number =", pcap_headers[2])
print("GMT to local correction =", pcap_headers[3])
print("Timestamp accuracy =", pcap_headers[4])
print("Snaplen =", pcap_headers[5])
print("Linktype =", pcap_headers[6])
print()

packet, first_time, count = 0, 0, 0
rep_src_mac, rep_dst_mac, rep_src_ip, rep_dst_ip, rep_src_port, rep_dst_port = '', '', '', '', '', ''
prev_mac = original_attacker_mac

# Random port number 
if cfg_list[12] == 'random':
    replay_attacker_port = random.randrange(5001,49151)

for(pkt_data, pkt_metadata) in RawPcapReader(pcap_file): 
    # Packet header information
    print("Packet", packet)

    # Logic to keep track of replacement values
    eth_pkt = Ether(pkt_data)
    curr_mac = eth_pkt.src
    if packet == 0:
        rep_src_mac = replay_attacker_mac
        rep_dst_mac = replay_victim_mac
        rep_src_ip = replay_attacker_ip
        rep_dst_ip = replay_victim_ip
        rep_src_port = replay_attacker_port
        rep_dst_port = replay_victim_port
    elif count == 1:
        if curr_mac == prev_mac:
            rep_src_mac = replay_attacker_mac
            rep_dst_mac = replay_victim_mac
            rep_src_ip = replay_attacker_ip
            rep_dst_ip = replay_victim_ip
            rep_src_port = replay_attacker_port
            rep_dst_port = replay_victim_port
        else:
            rep_src_mac = replay_victim_mac
            rep_dst_mac = replay_attacker_mac
            rep_src_ip = replay_victim_ip
            rep_dst_ip = replay_attacker_ip
            rep_src_port = replay_victim_port
            rep_dst_port = replay_attacker_port
    elif count == 2:
        if curr_mac != prev_mac:
            rep_src_mac = replay_victim_mac
            rep_dst_mac = replay_attacker_mac
            rep_src_ip = replay_victim_ip
            rep_dst_ip = replay_attacker_ip
            rep_src_port = replay_victim_port
            rep_dst_port = replay_attacker_port
        else:
            rep_src_mac = replay_attacker_mac
            rep_dst_mac = replay_victim_mac
            rep_src_ip = replay_attacker_ip
            rep_dst_ip = replay_victim_ip
            rep_src_port = replay_attacker_port
            rep_dst_port = replay_victim_port
        count = 0
    elif count == 0:
        rep_src_mac = replay_victim_mac
        rep_dst_mac = replay_attacker_mac
        rep_src_ip = replay_victim_ip
        rep_dst_ip = replay_attacker_ip
        rep_src_port = replay_victim_port
        rep_dst_port = replay_attacker_port
    count = count + 1
    packet = packet + 1
        
    # Relative time calculations
    if first_time == 0:
        first_time = 1
        b_sec = pkt_metadata.sec
        b_usec = pkt_metadata.usec
    c_sec = pkt_metadata.sec - b_sec
    c_usec = pkt_metadata.usec - b_usec
    while(c_usec < 0):
        c_usec = c_usec + 1000000
        c_sec = c_sec - 1
    print("%d.%06d" % (c_sec, c_usec))
    print("Captured Packet Length =", pkt_metadata.caplen)
    print("Actual Packet Length =", pkt_metadata.wirelen)

    if 'type' not in eth_pkt.fields:
        continue
    # Ethernet information
    print("Ethernet Header")
    print(s + "eth_src =", eth_pkt.src)
    print(s + "rep_src =", rep_src_mac)
    print(s + "eth_dst =", eth_pkt.dst)
    print(s + "rep_dst =", rep_dst_mac)
   
    # Check protocol 
    if eth_pkt.type == 0x0800:
        # IP information
        ip_pkt = eth_pkt[IP]
        print(s + "IP")
        print(s * 2 + "ip_len =", ip_pkt.len)
        print(s * 2 + "ip_src =", ip_pkt.src)
        print(s * 2 + "rep_src =", rep_src_ip)
        print(s * 2 + "ip_dst =", ip_pkt.dst)
        print(s * 2 + "rep_dst =", rep_dst_ip)
        if ip_pkt.proto == 6:
            # TCP information
            tcp_pkt = ip_pkt[TCP]
            print(s * 2 + "TCP")
            print(s * 3 + "Src Port =", rep_src_port)
            print(s * 3 + "Dst Port =", rep_dst_port)
            print(s * 3 + "Seq =", tcp_pkt.seq)
            print(s * 3 + "Ack =", tcp_pkt.ack)
        else:
            print("Other")
            continue
    else:
        print("Other")
    if send_pack == False:
        print()
        print(s + "Packet not sent")
    else:
        if timing == 'continuous':
            time.sleep(0)
        elif timing == 'delay':
            time.sleep(0.0005)
        # Only replay attacker packets
        if replay_attacker_ip == rep_src_ip:
            print(s + "Packet sent")
            sendp(Ether(src=rep_src_mac,dst=rep_dst_mac)/IP(src=rep_src_ip,dst=rep_dst_ip)/TCP(sport=int(rep_src_port),dport=int(rep_dst_port),seq=tcp_pkt.seq,ack=tcp_pkt.ack))
            pkts = sniff(count=5, filter="tcp and host " + replay_victim_ip, iface="enp0s25", timeout=1)
            pkts.summary()

    print()
