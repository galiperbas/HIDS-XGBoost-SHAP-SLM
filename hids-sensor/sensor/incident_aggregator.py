"""
incident_aggregator.py — Ham tespitleri "olay (incident)" haline toplar.

PROBLEM (alarm yorgunluğu / alert fatigue):
Tek bir saldırı (örn. port tarama) paket-başına yüzlerce ham alarm üretir.
Ayrıca hibrit dedektör (kural + XGBoost) ve çift-yön yakalama (MITM) AYNI trafiğe
farklı etiketler verir: giden tarama → PortScan, kurbanın dönen RST cevapları →
DoS_Flood, akış-bazlı model → ML_Detected ... Sonuç: tek mantıksal olay binlerce
alarma ve birden çok Telegram bildirimine bölünür.

ÇÖZÜM:
Aynı host çifti (yön-bağımsız) için belirli bir zaman penceresinde gelen ham
tespitleri TEK olaya indirger. Olay kapandığında (boşta kalma süresi dolunca ya
da çok uzarsa) tek bir özet olay yayınlanır:
  - baskın etiket = öncelik tablosundaki en yüksek tür (örn. PortScan)
  - hits = birleştirilen ham alarm sayısı
  - en yüksek tehdit skoru, süre ve tür dağılımı

ÖNEMLİ: Bu katman YALNIZCA buluta push + dashboard + bildirim içindir. Ham
tespitler yine de detections.jsonl'a yazılır; böylece bilimsel değerlendirme
(evaluate_live.ipynb, precision/recall) ETKİLENMEZ.
"""

import time
from datetime import datetime

# Baskın etiket önceliği (yüksek -> düşük). Bir olayda birden çok tür ateşlenirse
# en yüksek öncelikli tür olayın etiketi olur. Eşitlikte en çok görülen kazanır.
_PRIORITY = [
    "PortScan", "Recon_Scan", "BruteForce",
    "SYN_Flood", "DoS_Flood", "DDoS_HTTP", "Mirai_Botnet", "Slowloris",
    "ML_Detected",
]
_RANK = {t: i for i, t in enumerate(_PRIORITY)}

_MITRE = {
    "PortScan": "T1046", "Recon_Scan": "T1046",
    "SYN_Flood": "T1498", "DoS_Flood": "T1498", "DDoS_HTTP": "T1498",
    "Mirai_Botnet": "T1498", "BruteForce": "T1110", "Slowloris": "T1499",
    "ML_Detected": "T1190",
}


class _Incident:
    __slots__ = ("id", "first", "last", "types", "max_score", "samples",
                 "method", "shap_top")

    def __init__(self, now: float, iid: int):
        self.id = iid
        self.first = now
        self.last = now
        self.types: dict[str, int] = {}      # attack_type -> sayı
        self.max_score = 0
        self.samples: dict[str, tuple] = {}  # attack_type -> (src, dst) örneği
        self.method = "rule"
        self.shap_top: list = []


class IncidentAggregator:
    """Ham tespitleri host-çifti + zaman penceresine göre tek olaya toplar."""

    def __init__(self, window_sec: float = 10.0, max_incident_sec: float = 30.0):
        # window_sec: bu kadar süre yeni tespit gelmezse olay KAPANIR ve yayınlanır.
        # max_incident_sec: çok uzun süren saldırıda olay bu süre dolunca yayınlanır
        #                   (dashboard çok uzun sessiz kalmasın), sonra yenisi başlar.
        self.window_sec = window_sec
        self.max_incident_sec = max_incident_sec
        self._incidents: dict[tuple, _Incident] = {}
        self._seq = 0

    @staticmethod
    def _key(log: dict) -> tuple:
        # Yön-bağımsız: (A->B) ve (B->A) aynı olaya katlanır → dönüş trafiği ayrı
        # "saldırı" sayılmaz.
        a = log.get("source_ip") or "?"
        b = log.get("destination_ip") or "?"
        return tuple(sorted((a, b)))

    def add(self, log: dict) -> None:
        """Bir ham tespiti ilgili olaya ekle (yayınlamaz)."""
        now = time.time()
        key = self._key(log)
        inc = self._incidents.get(key)
        if inc is None:
            self._seq += 1
            inc = _Incident(now, self._seq)
            self._incidents[key] = inc
        inc.last = now

        at = log.get("attack_type") or "ML_Detected"
        inc.types[at] = inc.types.get(at, 0) + 1
        inc.samples.setdefault(at, (log.get("source_ip", ""), log.get("destination_ip", "")))

        score = int(log.get("threat_score", 0) or 0)
        if score > inc.max_score:
            inc.max_score = score
        if log.get("method") == "xgboost" and inc.method == "rule":
            inc.method = "hybrid"
        if log.get("shap_top"):
            inc.shap_top = log["shap_top"]

    def _dominant(self, inc: _Incident) -> str:
        present = sorted(inc.types.keys(),
                         key=lambda t: (_RANK.get(t, 999), -inc.types[t]))
        return present[0] if present else "ML_Detected"

    def _build(self, inc: _Incident) -> dict:
        dom = self._dominant(inc)
        src, dst = inc.samples.get(dom, ("", ""))
        hits = sum(inc.types.values())
        dur = max(inc.last - inc.first, 0.0)
        score = inc.max_score
        status = "CRITICAL" if score >= 70 else "MEDIUM" if score >= 35 else "SAFE"
        types_str = ", ".join(f"{t}×{c}" for t, c in
                              sorted(inc.types.items(), key=lambda x: -x[1]))
        return {
            "id": f"inc-{inc.id}",
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "ts_iso": datetime.now().isoformat(timespec="milliseconds"),
            "ts_epoch": time.time(),
            "source_ip": src,
            "destination_ip": dst,
            "protocol": dom,
            "threat_score": score,
            "status": status,
            "label": "ANOMALY",
            "attack_type": dom,
            "mitre": _MITRE.get(dom, ""),
            "method": inc.method,
            "confidence": 0.0,
            "flow_packets": hits,
            "inference_ms": 0.0,
            "shap_top": inc.shap_top,
            # ── olay-özel alanlar ──
            "event_kind": "incident",
            "hits": hits,
            "duration_s": round(dur, 1),
            "types": dict(inc.types),
            "reason": (f"{hits} ham alarm tek olayda birleştirildi · "
                       f"{round(dur)}s · {types_str}"),
        }

    def flush(self) -> list:
        """Boşta kalan ya da çok uzayan olayları yayınla (ve kapat)."""
        now = time.time()
        out, done = [], []
        for key, inc in self._incidents.items():
            if (now - inc.last) >= self.window_sec or (now - inc.first) >= self.max_incident_sec:
                out.append(self._build(inc))
                done.append(key)
        for k in done:
            del self._incidents[k]
        return out

    def drain(self) -> list:
        """Kapanışta kalan tüm açık olayları yayınla."""
        out = [self._build(inc) for inc in self._incidents.values()]
        self._incidents.clear()
        return out
