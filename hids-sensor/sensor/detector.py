"""
detector.py — Anomali/saldırı tespit motoru.

İki katman:
  1. Kural tabanlı tespit (port scan, SYN flood) — anında çalışır
  2. XGBoost modeli (eğitilmiş model varsa) — öğrenme tabanlı tespit

Eğitilmiş XGBoost modelini entegre etmek için:
  - Benchmark'tan modeli kaydet: joblib.dump(model, "model.joblib")
  - AnomalyDetector(model_path="model.joblib") ile başlat
"""

import time
from dataclasses import dataclass
from typing import Optional

try:
    from .sniffer import FlowFeatures
except ImportError:
    from sniffer import FlowFeatures


@dataclass
class Detection:
    label: str          # "NORMAL" / "ANOMALY"
    attack_type: str    # "BENIGN", "PortScan", "SYN_Flood", "BruteForce", vb.
    threat_score: int   # 0-100
    confidence: float
    method: str         # "rule" / "xgboost"
    inference_ms: float


class AnomalyDetector:
    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.use_xgboost = False

        if model_path:
            try:
                import joblib
                self.model = joblib.load(model_path)
                self.use_xgboost = True
                print(f"[DETECTOR] XGBoost modeli yüklendi: {model_path}")
            except Exception as e:
                print(f"[DETECTOR] Model yüklenemedi ({e}) — kural tabanlı moda geçiliyor.")

        if not self.use_xgboost:
            print("[DETECTOR] Kural tabanlı tespit aktif (XGBoost modeli eklenebilir).")

    def detect(self, f: FlowFeatures) -> Detection:
        start = time.perf_counter()

        # --- Katman 1: Kural tabanlı tespit ---
        rule_result = self._rule_based(f)
        if rule_result:
            rule_result.inference_ms = round((time.perf_counter() - start) * 1000, 3)
            return rule_result

        # --- Katman 2: XGBoost (varsa) ---
        if self.use_xgboost:
            return self._xgboost_predict(f, start)

        # Hiçbir kural tetiklenmedi → normal
        return Detection(
            label="NORMAL", attack_type="BENIGN", threat_score=5,
            confidence=0.90, method="rule",
            inference_ms=round((time.perf_counter() - start) * 1000, 3),
        )

    def _rule_based(self, f: FlowFeatures) -> Optional[Detection]:
        """Bilinen saldırı imzalarını kurallarla yakala."""

        # Port Scan: kısa sürede çok farklı porta erişim
        if f.unique_ports_last_sec >= 15:
            return Detection("ANOMALY", "PortScan",
                             min(60 + f.unique_ports_last_sec, 95),
                             0.92, "rule", 0)

        # SYN Flood: kısa sürede çok SYN paketi
        if f.syn_count_last_sec >= 30:
            return Detection("ANOMALY", "SYN_Flood",
                             min(70 + f.syn_count_last_sec // 5, 99),
                             0.95, "rule", 0)

        # Genel flood: tek kaynaktan aşırı paket
        if f.packets_last_sec >= 100:
            return Detection("ANOMALY", "DoS_Flood",
                             min(65 + f.packets_last_sec // 20, 98),
                             0.88, "rule", 0)

        # SSH/FTP brute force: 22/21'e tekrarlı bağlantı
        if f.dst_port in (22, 21) and f.packets_last_sec >= 20:
            return Detection("ANOMALY", "BruteForce",
                             min(60 + f.packets_last_sec, 95),
                             0.85, "rule", 0)

        return None

    def _xgboost_predict(self, f: FlowFeatures, start: float) -> Detection:
        """XGBoost ile tahmin (gerçek model entegrasyonu)."""
        # Öznitelik vektörü — kendi modelinin beklediği sıraya göre düzenle
        feature_vector = [[
            f.packet_size, f.ttl, f.src_port, f.dst_port,
            f.packets_last_sec, f.unique_ports_last_sec, f.syn_count_last_sec,
        ]]
        proba = self.model.predict_proba(feature_vector)[0]
        is_anomaly = proba[1] > 0.5
        score = int(proba[1] * 100)
        return Detection(
            label="ANOMALY" if is_anomaly else "NORMAL",
            attack_type="ML_Detected" if is_anomaly else "BENIGN",
            threat_score=score,
            confidence=round(float(max(proba)), 2),
            method="xgboost",
            inference_ms=round((time.perf_counter() - start) * 1000, 3),
        )
