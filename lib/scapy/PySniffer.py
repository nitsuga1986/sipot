from scapy.all import *
 
def pkt_callback(pkt):
    pkt.sprintf("{Raw:%Raw.load%\n}")
 
sniff(prn=lambda x:x.sprintf("{Raw:%Raw.load%\n}"), filter="ip and port 5060 ", store=0)
