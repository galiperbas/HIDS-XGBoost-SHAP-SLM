"""
sniffer.py — Canlı ağ paket yakalama (Scapy).

Host PC'de çalışır, Bridged moddaki VM'ler arası trafiği yakalar.
Her paketten temel öznitelikleri çıkarıp bir callback'e iletir.

Windows'ta Npcap gereklidir (Wireshark ile kurulur).
"""

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from scapy.all import sniff, IP, TCP, UDP, ICMP


@dataclass
class FlowFeatures:
    """Bir paket/akıştan çıkarılan öznitelikler."""
    timestamp: str
    source_ip: str
    destination_ip: str
    protocol: str
    src_port: int
    dst_port: int
    packet_size: int
    ttl: int
    tcp_flags: str
    # Akış-bazlı (son 1 saniyedeki kaynak IP davranışı)
    packets_last_sec: int
    unique_ports_last_sec: int
    syn_count_last_sec: int

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "packet_size": self.packet_size,
            "ttl": self.ttl,
            "tcp_flags": self.tcp_flags,
            "packets_last_sec": self.packets_last_sec,
            "unique_ports_last_sec": self.unique_ports_last_sec,
            "syn_count_last_sec": self.syn_count_last_sec,
        }


class LiveSniffer:
    """Scapy tabanlı canlı paket yakalayıcı + akış istatistikleri."""

    def __init__(self, iface: Optional[str] = None, bpf_filter: str = "ip"):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self._running = False
        # Kaynak IP başına son 1 saniyelik aktivite penceresi
        self._activity = defaultdict(lambda: deque(maxlen=500))

    def _window_stats(self, src_ip: str, dst_port: int, is_syn: bool):
        """Kaynak IP için son 1 saniyedeki davranış istatistiklerini hesapla."""
        now = time.time()
        window = self._activity[src_ip]
        window.append((now, dst_port, is_syn))

        # 1 saniyeden eski kayıtları at
        while window and now - window[0][0] > 1.0:
            window.popleft()

        packets = len(window)
        unique_ports = len(set(p for _, p, _ in window))
        syn_count = sum(1 for _, _, s in window if s)
        return packets, unique_ports, syn_count

    def _extract(self, pkt) -> Optional[FlowFeatures]:
        """Scapy paketinden öznitelik çıkar."""
        if not pkt.haslayer(IP):
            return None

        ip = pkt[IP]
        proto = "OTHER"
        src_port = dst_port = 0
        flags = "-"
        is_syn = False

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            proto = "TCP"
            src_port, dst_port = tcp.sport, tcp.dport
            flags = str(tcp.flags)
            is_syn = "S" in flags and "A" not in flags
        elif pkt.haslayer(UDP):
            proto = "UDP"
            src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            proto = "ICMP"

        port_map = {80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 21: "FTP", 8080: "HTTP-ALT"}
        proto = port_map.get(dst_port, proto)

        pkts, uports, syns = self._window_stats(ip.src, dst_port, is_syn)

        return FlowFeatures(
            timestamp=datetime.now().strftime("%H:%M:%S.%f")[:-3],
            source_ip=ip.src,
            destination_ip=ip.dst,
            protocol=proto,
            src_port=src_port,
            dst_port=dst_port,
            packet_size=len(pkt),
            ttl=ip.ttl,
            tcp_flags=flags,
            packets_last_sec=pkts,
            unique_ports_last_sec=uports,
            syn_count_last_sec=syns,
        )

    def start(self, callback: Callable[[FlowFeatures], None]):
        """
        Paket yakalamayı başlat.

        Args:
            callback: Her paket için çağrılacak fonksiyon (FlowFeatures alır)
        """
        self._running = True

        def _on_packet(pkt):
            if not self._running:
                return
            features = self._extract(pkt)
            if features:
                callback(features)

        print(f"[SNIFFER] Yakalama başladı (iface={self.iface or 'default'}, filter='{self.bpf_filter}')")
        sniff(
            iface=self.iface,
            prn=_on_packet,
            filter=self.bpf_filter,
            store=False,
            stop_filter=lambda _: not self._running,
        )

    def stop(self):
        self._running = False
        print("[SNIFFER] Durduruldu.")


def list_interfaces():
    """Mevcut ağ arayüzlerini listele (hangi iface'i kullanacağını bulmak için)."""
    from scapy.all import get_if_list
    print("Mevcut arayüzler:")
    for i, iface in enumerate(get_if_list()):
        print(f"  [{i}] {iface}")


if __name__ == "__main__":
    # Test: arayüzleri listele, sonra yakalamayı dene
    list_interfaces()
    s = LiveSniffer()
    s.start(lambda f: print(f.to_dict()))
