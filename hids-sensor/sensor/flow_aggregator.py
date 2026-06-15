"""
flow_aggregator.py — Paketleri akışlara topla, öznitelik vektörü üret.

Paket-bazlı sniffer çıktısını alır, (src_ip, dst_ip, servis portu) bazında
gruplar ve zaman penceresi dolunca öznitelik vektörü üretir. Bu vektör doğrudan
XGBoost modeline beslenir.

AKADEMİK DÜRÜSTLÜK NOTU
-----------------------
CICIoT2023'ün 46 özniteliğinin TAMAMI canlı paketlerden sadık biçimde yeniden
üretilemez. Bu yüzden burada YALNIZCA canlı ortamda standart, belirsizlik
içermeyen tanımlarla hesaplanabilen öznitelikler tutulur (aşağıdaki FEATURE_NAMES,
40 öznitelik). Tanımını veri setinin çıkarıcısıyla birebir eşleştiremediğimiz
kompozit öznitelikler ("Magnitue", "Radius", "Covariance", "Weight", "Duration"
(TTL), "Tot size") KASITLI OLARAK DIŞARIDA BIRAKILMIŞTIR — uydurma/yaklaşık
değer üretilmez. Colab eğitim defteri de modeli AYNI 40 öznitelikle (aynı sırada)
eğitir; böylece eğitim ile canlı çıkarım arasında öznitelik kayması (train/serve
skew) ortadan kalkar.
"""

import time
import numpy as np
from dataclasses import dataclass, field
from typing import Optional, Callable

try:
    from .sniffer import FlowFeatures
except ImportError:
    from sniffer import FlowFeatures

# Canlı ortamda sadık biçimde hesaplanabilen öznitelikler (feature_names.json ile
# ve Colab eğitim defteriyle BİREBİR aynı isim ve sıra olmalıdır).
FEATURE_NAMES = [
    "flow_duration", "Header_Length", "Protocol Type",
    "Rate", "Srate", "Drate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number",
    "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number",
    "ack_count", "syn_count", "fin_count", "urg_count", "rst_count",
    "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC",
    "TCP", "UDP", "DHCP", "ARP", "ICMP", "IPv", "LLC",
    "Tot sum", "Min", "Max", "AVG", "Std", "IAT", "Number", "Variance",
]

# Bu portlarda görülen trafik ilgili protokol bayrağını (one-hot) 1 yapar.
_PORT_PROTO = {
    80: "HTTP", 8080: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH",
    23: "Telnet", 25: "SMTP", 6667: "IRC", 67: "DHCP", 68: "DHCP",
}


@dataclass
class FlowState:
    """Tek bir akışın birikimli durumu."""
    start_time: float = 0.0
    last_time: float = 0.0
    packet_sizes: list = field(default_factory=list)
    timestamps: list = field(default_factory=list)
    header_total: int = 0          # toplam başlık uzunluğu (bayt)
    # TCP flag sayaçları
    fin: int = 0
    syn: int = 0
    rst: int = 0
    psh: int = 0
    ack: int = 0
    ece: int = 0
    cwr: int = 0
    urg: int = 0
    # Kimlik / protokol
    ip_proto: int = 0
    protocol: str = "TCP"
    src_ip: str = ""               # akışı BAŞLATAN taraf (yön referansı)
    dst_ip: str = ""
    dst_port: int = 0
    # Yön sayaçları
    fwd_count: int = 0             # src_ip -> dst_ip
    bwd_count: int = 0             # dst_ip -> src_ip
    # Görülen protokoller (one-hot için)
    protos_seen: set = field(default_factory=set)


class FlowAggregator:
    """
    Paketleri akışlara toplar, pencere dolunca FEATURE_NAMES sırasında bir
    öznitelik vektörü üretir.

    Args:
        window_sec: Akış pencere süresi (saniye)
        on_flow: Akış tamamlandığında çağrılacak callback (vec, state)
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

    def _mark_protocols(self, f: FlowFeatures, state: FlowState):
        """Bu paketten görülen protokolleri işaretle (one-hot için)."""
        state.protos_seen.add("IPv")  # IP paketi
        if f.ip_proto == 6:
            state.protos_seen.add("TCP")
        elif f.ip_proto == 17:
            state.protos_seen.add("UDP")
        elif f.ip_proto == 1:
            state.protos_seen.add("ICMP")
        for port in (f.dst_port, f.src_port):
            name = _PORT_PROTO.get(port)
            if name:
                state.protos_seen.add(name)

    def add_packet(self, f: FlowFeatures):
        """Paketi ilgili akışa ekle."""
        now = time.time()
        key = self._flow_key(f)

        if key not in self._flows:
            self._flows[key] = FlowState(
                start_time=now, last_time=now,
                src_ip=f.source_ip, dst_ip=f.destination_ip,
                dst_port=f.dst_port, protocol=f.protocol,
                ip_proto=f.ip_proto,
            )

        state = self._flows[key]
        state.last_time = now
        state.packet_sizes.append(f.packet_size)
        state.timestamps.append(now)
        state.header_total += f.header_length

        # Yön: paketin kaynağı akışı başlatan taraf mı?
        if f.source_ip == state.src_ip:
            state.fwd_count += 1
        else:
            state.bwd_count += 1

        self._parse_flags(f.tcp_flags, state)
        self._mark_protocols(f, state)

        # Pencere kontrolü
        if now - state.start_time >= self.window_sec:
            self._emit_flow(key)

        # Periyodik temizlik
        if now - self._last_cleanup > self.window_sec * 2:
            self._cleanup(now)

    def _emit_flow(self, key: str):
        """Akışı öznitelik vektörüne dönüştür ve callback'e gönder."""
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
        """FlowState'ten FEATURE_NAMES sırasında öznitelik vektörü hesapla."""
        sizes = np.array(s.packet_sizes, dtype=np.float64)
        times = np.array(s.timestamps, dtype=np.float64)
        n = len(sizes)

        duration = max(s.last_time - s.start_time, 0.001)
        rate = n / duration
        srate = s.fwd_count / duration
        drate = s.bwd_count / duration

        tot_sum = float(sizes.sum())
        mn = float(sizes.min())
        mx = float(sizes.max())
        avg = float(sizes.mean())
        std = float(sizes.std()) if n > 1 else 0.0
        variance = float(sizes.var()) if n > 1 else 0.0
        iat = float(np.diff(times).mean()) if n > 1 else 0.0

        # *_flag_number = ilgili flag akışta hiç görüldü mü (0/1)
        def seen(c: int) -> int:
            return 1 if c > 0 else 0

        oh = {p: (1 if p in s.protos_seen else 0) for p in
              ["HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC",
               "TCP", "UDP", "DHCP", "ARP", "ICMP", "IPv", "LLC"]}

        vec = np.array([
            duration,            # flow_duration
            float(s.header_total),  # Header_Length
            float(s.ip_proto),   # Protocol Type (gerçek IP protokol numarası)
            rate,                # Rate
            srate,               # Srate
            drate,               # Drate
            seen(s.fin),         # fin_flag_number
            seen(s.syn),         # syn_flag_number
            seen(s.rst),         # rst_flag_number
            seen(s.psh),         # psh_flag_number
            seen(s.ack),         # ack_flag_number
            seen(s.ece),         # ece_flag_number
            seen(s.cwr),         # cwr_flag_number
            s.ack,               # ack_count
            s.syn,               # syn_count
            s.fin,               # fin_count
            s.urg,               # urg_count
            s.rst,               # rst_count
            oh["HTTP"], oh["HTTPS"], oh["DNS"], oh["Telnet"], oh["SMTP"],
            oh["SSH"], oh["IRC"], oh["TCP"], oh["UDP"], oh["DHCP"],
            oh["ARP"], oh["ICMP"], oh["IPv"], oh["LLC"],
            tot_sum,             # Tot sum
            mn,                  # Min
            mx,                  # Max
            avg,                 # AVG
            std,                 # Std
            iat,                 # IAT
            float(n),            # Number
            variance,            # Variance
        ], dtype=np.float64)

        return vec
