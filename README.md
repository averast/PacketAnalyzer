# Packet Analyzer
This program will read in packet captures and parse out the packet information.

# Sample Output
```
PCAP_MAGIC
Version major number = 2
Version minor number = 4
GMT to local correction = 0
Timestamp accuracy = 0
Snaplen = 262144
Linktype = 1

Packet 0
0.000000
Captured Packet Length = 74
Actual Packet Length = 74
Ethernet Header
   eth_src = a8:f0:c4:5c:91:84
   rep_src = 00:24:e8:fc:58:7b
   eth_dst = 14:7e:75:1f:8d:9a
   rep_dst = 00:50:56:9a:03:ad
   IP
      ip_len = 60
      ip_src = 10.42.126.178
      rep_src = 192.168.2.127
      ip_dst = 10.42.38.90
      rep_dst = 192.168.3.54
      TCP
         Src Port = 15349
         Dst Port = 79
         Seq = 1052403918
         Ack = 0
   Packet sent

Sent 1 packets.
Ether / IP / TCP 192.168.3.54:finger > 192.168.2.127:15349 SA / Padding

Packet 1
0.000283
Captured Packet Length = 74
Actual Packet Length = 74
Ethernet Header
   eth_src = 14:7e:75:1f:8d:9a
   rep_src = 00:50:56:9a:03:ad
   eth_dst = a8:f0:c4:5c:91:84
   rep_dst = 00:24:e8:fc:58:7b
   IP
      ip_len = 60
      ip_src = 10.42.38.90
      rep_src = 192.168.3.54
      ip_dst = 10.42.126.178
      rep_dst = 192.168.2.127
      TCP
         Src Port = 79
         Dst Port = 15349
         Seq = 518738534
         Ack = 1052403919

Packet 2
0.000301
Captured Packet Length = 66
Actual Packet Length = 66
Ethernet Header
   eth_src = a8:f0:c4:5c:91:84
   rep_src = 00:24:e8:fc:58:7b
   eth_dst = 14:7e:75:1f:8d:9a
   rep_dst = 00:50:56:9a:03:ad
   IP
      ip_len = 52
      ip_src = 10.42.126.178
      rep_src = 192.168.2.127
      ip_dst = 10.42.38.90
      rep_dst = 192.168.3.54
      TCP
         Src Port = 15349
         Dst Port = 79
         Seq = 1052403919
         Ack = 518738535
   Packet sent

...
```
