#!/usr/bin/env python3
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send
from time import time
import hmac, hashlib
import argparse

p = argparse.ArgumentParser(description='eBPF port knocking tool - Client.', formatter_class=argparse.RawTextHelpFormatter)
p.add_argument('-s', '--secret', metavar='KEY ', type=str, help='HMAC secret key', required=True)
p.add_argument('-t', '--time', metavar='TIME', type=int, help='generated HMAC duration', required=True)
p.add_argument('-d', '--dst', metavar='IP', type=str, help='destination IP address', required=True)
p.add_argument('-p', '--port', metavar='PORT', type=str, help='monitored port', required=True)

args = p.parse_args()

timestamp       = int(time()//args.time)

h    = hmac.new(args.secret.encode(), int.to_bytes(timestamp, 8, byteorder='little'), hashlib.md5)
h    = h.digest()

id   = int.from_bytes(h[0:2], byteorder='little')
seq  = int.from_bytes(h[2:6], byteorder='little')
win  = int.from_bytes(h[6:8], byteorder='little')
tcp_port = int.from_bytes(h[8:10], byteorder='little')

print(tcp_port)

syn = TCP(dport=int(args.port), flags='S', seq=seq, window=win)
ip  = IP(dst=args.dst, id=id)
send(ip/syn, verbose=False)

