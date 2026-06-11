"""
flow_aggregator.py — Paketleri akışlara topla, CICIoT2023 özniteliklerini hesapla.

Paket-bazlı sniffer çıktısını alır, (src_ip, dst_ip, dst_port) bazında
gruplar ve belirli zaman penceresi dolunca 46 özniteliklik vektör üretir.
Bu vektör doğrudan XGBoost modeline beslenir.
"""

import time
import math
import numpy as np
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, List, Callable

try:
    from .sniffer import FlowFeatures
except ImportError:
    from sniffer import FlowFeatures

# CICIoT2023 öznitelik sırası (feature_names.json ile birebir)
FEATURE_NAMES = [
    "flow_duration", "Header_Length", "Protocol Type", "Duration",
    "Rate", "Srate", "Drate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number",
    "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number",
    "ack_count", "syn_count", "fin_count", "urg_count", "rst_count",
    "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC",
    "TCP", "UDP", "DHCP", "ARP", "ICMP", "IPv", "LLC",
    "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT",
    "Number", "Magnitue", "Radius", "Covariance", "Variance", "Weight",
]

# Protokol -> flag haritası
PROTO_MAP = {
    "HTTP": "HTTP", "HTTPS": "HTTPS", "DNS": "DNS", "SSH": "SSH",
    "FTP": "Telnet",  # FTP yakın kategori
    "TCP": "TCP", "UDP": "UDP", "ICMP": "ICMP", "HTTP-ALT": "HTTP",
    "OTHER": "IPv",
}


@dataclass
class FlowState:
    """Tek bir akışın birikimli durumu."""
    start_time: float = 0.0
    last_time: float = 0.0
    packet_sizes: list = field(default_factory=list)
    timestamps: list = field(default_factory=list)
    header_lengths: list = field(default_factory=list)
    # TCP flag sayaçları
    fin: int = 0
    syn: int = 0
    rst: int = 0
    psh: int = 0
    ack: int = 0
    ece: int = 0
    cwr: int = 0
    urg: int = 0
    # Protokol
    protocol: str = "TCP"
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    # Yön sayaçları
    fwd_count: int = 0  # source -> dest
    bwd_count: int = 0  # dest -> source


class FlowAggregator:
    """
    Paketleri akışlara toplar, pencere dolunca 46 öznitelik vektörü üretir.

    Args:
        window_sec: Akış pencere süresi (saniye)
        on_flow: Akış tamamlandığında çağrılacak callback
    """

    def __init__(self, window_sec: float = 3.0, on_flow: Optional[Callable] = None):
        self.window_sec = window_sec
        self.on_flow = on_flow
        self._flows: dict[str, FlowState] = {}
        self._last_cleanup = time.time()

    def _flow_key(self, f: FlowFeatures) -> str:
        # İki yönlü akış: (A->B) ve (B->A) aynı akış
        ips = tuple(sorted([f.source_ip, f.destination_ip]))
        port = min(f.src_port, f.dst_port)  # Küçük port genelde servis portu
        return f"{ips[0]}:{ips[1]}:{port}"

    def _parse_flags(self, flags_str: str, state: FlowState):
        """TCP flag string'inden sayaçları güncelle."""
        if flags_str == "-":
            return
        f = flags_str.upper()
        if 'F' in f: state.fin += 1
        if 'S' in f: state.syn += 1
        if 'R' in f: state.rst += 1
        if 'P' in f: state.psh += 1
        if 'A' in f: state.ack += 1
        if 'E' in f: state.ece += 1
        if 'C' in f: state.cwr += 1
        if 'U' in f: state.urg += 1

    def add_packet(self, f: FlowFeatures):
        """Paketi ilgili akışa ekle."""
        now = time.time()
        key = self._flow_key(f)

        if key not in self._flows:
            self._flows[key] = FlowState(
                start_time=now, last_time=now,
                src_ip=f.source_ip, dst_ip=f.destination_ip,
                dst_port=f.dst_port, protocol=f.protocol,
            )

        state = self._flows[key]
        state.last_time = now
        state.packet_sizes.append(f.packet_size)
        state.timestamps.append(now)
        state.header_lengths.append(min(f.packet_size, 54))  # IP+TCP header ~54
        state.fwd_count += 1
        self._parse_flags(f.tcp_flags, state)

        # Pencere kontrolü
        if now - state.start_time >= self.window_sec:
            self._emit_flow(key)

        # Periyodik temizlik
        if now - self._last_cleanup > self.window_sec * 2:
            self._cleanup(now)

    def _emit_flow(self, key: str):
        """Akışı 46 özniteliğe dönüştür ve callback'e gönder."""
        state = self._flows.pop(key, None)
        if state is None or len(state.packet_sizes) < 2:
            return

        vec = self._compute_features(state)
        if self.on_flow:
            self.on_flow(vec, state)

    def _cleanup(self, now: float):
        """Süresi dolan akışları emit et."""
        self._last_cleanup = now
        expired = [k for k, v in self._flows.items()
                   if now - v.last_time > self.window_sec]
        for k in expired:
            self._emit_flow(k)

    def _compute_features(self, s: FlowState) -> np.ndarray:
        """FlowState'ten 46 boyutlu öznitelik vektörü hesapla."""
        sizes = np.array(s.packet_sizes, dtype=np.float64)
        times = np.array(s.timestamps, dtype=np.float64)
        n = len(sizes)

        # Temel metrikler
        duration = max(s.last_time - s.start_time, 0.001)
        rate = n / duration
        srate = s.fwd_count / duration
        drate = s.bwd_count / duration if s.bwd_count > 0 else 0

        # Paket boyut istatistikleri
        tot_sum = float(sizes.sum())
        mn = float(sizes.min())
        mx = float(sizes.max())
        avg = float(sizes.mean())
        std = float(sizes.std()) if n > 1 else 0.0

        # Inter-arrival time
        if n > 1:
            iats = np.diff(times)
            iat = float(iats.mean())
        else:
            iat = 0.0

        # İstatistiksel öznitelikler
        magnitude = float(np.sqrt(np.sum(sizes ** 2)))
        radius = float(np.sqrt(std ** 2)) if std > 0 else 0.0
        variance = float(np.var(sizes))
        if n > 1 and iat > 0:
            covariance = float(np.cov(sizes[:min(n, len(times))],
                                       times[:min(n, len(sizes))])[0][1]) if n > 2 else 0.0
        else:
            covariance = 0.0
        weight = n / duration if duration > 0 else 0

        # Protokol one-hot
        proto = PROTO_MAP.get(s.protocol, "IPv")
        proto_flags = {p: 0 for p in ["HTTP","HTTPS","DNS","Telnet","SMTP",
                                       "SSH","IRC","TCP","UDP","DHCP","ARP",
                                       "ICMP","IPv","LLC"]}
        if proto in proto_flags:
            proto_flags[proto] = 1
        # TCP/UDP base protokol de işaretle
        if s.protocol in ("HTTP", "HTTPS", "SSH", "FTP", "DNS", "HTTP-ALT"):
            proto_flags["TCP"] = 1

        # Header length toplamı
        header_len = sum(s.header_lengths)

        # 46 öznitelik vektörü (FEATURE_NAMES sırasıyla)
        vec = np.array([
            duration,           # flow_duration
            header_len,         # Header_Length
            hash(s.protocol) % 20,  # Protocol Type (sayısal)
            duration,           # Duration
            rate,               # Rate
            srate,              # Srate
            drate,              # Drate
            s.fin,              # fin_flag_number
            s.syn,              # syn_flag_number
            s.rst,              # rst_flag_number
            s.psh,              # psh_flag_number
            s.ack,              # ack_flag_number
            s.ece,              # ece_flag_number
            s.cwr,              # cwr_flag_number
            s.ack,              # ack_count
            s.syn,              # syn_count
            s.fin,              # fin_count
            s.urg,              # urg_count
            s.rst,              # rst_count
            proto_flags["HTTP"],
            proto_flags["HTTPS"],
            proto_flags["DNS"],
            proto_flags["Telnet"],
            proto_flags["SMTP"],
            proto_flags["SSH"],
            proto_flags["IRC"],
            proto_flags["TCP"],
            proto_flags["UDP"],
            proto_flags["DHCP"],
            proto_flags["ARP"],
            proto_flags["ICMP"],
            proto_flags["IPv"],
            proto_flags["LLC"],
            tot_sum,            # Tot sum
            mn,                 # Min
            mx,                 # Max
            avg,                # AVG
            std,                # Std
            tot_sum,            # Tot size
            iat,                # IAT
            n,                  # Number
            magnitude,          # Magnitue (dataset'teki typo)
            radius,             # Radius
            covariance,         # Covariance
            variance,           # Variance
            weight,             # Weight
        ], dtype=np.float64)

        return vec
