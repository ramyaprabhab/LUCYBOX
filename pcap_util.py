
from scapy.all import rdpcap, PcapReader
from typing import Iterator
def count_packets(path:str)->int:
    pkts = rdpcap(path); return len(pkts)
def stream_pcap(path:str)->Iterator:
    with PcapReader(path) as reader:
        for pkt in reader:
            yield pkt
def packet_summary(pkt):
    try:
        src = getattr(pkt, "src", None) or (pkt[0].src if len(pkt.layers())>0 else None)
    except Exception:
        src = None
    try:
        dst = getattr(pkt, "dst", None) or (pkt[0].dst if len(pkt.layers())>0 else None)
    except Exception:
        dst = None
    proto = pkt.__class__.__name__
    length = len(pkt) if hasattr(pkt, "__len__") else None
    return {"src": str(src), "dst": str(dst), "proto": proto, "len": length}
