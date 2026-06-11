"""
detector.py — Hibrit anomali tespit motoru.

Katman 1: Kural tabanlı (anlık, paket-bazlı) — port scan, SYN flood, brute force
Katman 2: XGBoost (akış-bazlı) — CICIoT2023 ile eğitilmiş model

Her iki katman paralel çalışır. Kural tabanlı hızlı alarm verir,
XGBoost akış penceresi dolunca daha doğru sınıflandırma yapar.
"""

import os
import time
import json
import numpy as np
from dataclasses import dataclass
from typing import Optional

try:
    from .sniffer import FlowFeatures
    from .flow_aggregator import FlowAggregator, FlowState
except ImportError:
    from sniffer import FlowFeatures
    from flow_aggregator import FlowAggregator, FlowState


@dataclass
class Detection:
    label: str          # "NORMAL" / "ANOMALY"
    attack_type: str    # "BENIGN", "PortScan", "SYN_Flood", "BruteForce", "ML_Detected" vb.
    threat_score: int   # 0-100
    confidence: float
    method: str         # "rule" / "xgboost"
    inference_ms: float
    # Akış bilgisi (XGBoost tespitlerinde dolu)
    flow_src: str = ""
    flow_dst: str = ""
    flow_packets: int = 0


class AnomalyDetector:
    def __init__(self, models_dir: str = "models"):
        self.model = None
        self.scaler = None
        self.feature_names = None
        self.use_xgboost = False
        self.flow_aggregator = None
        self._pending_detections: list[Detection] = []

        # XGBoost model yükle
        model_path = os.path.join(models_dir, "xgboost_ciciot2023.joblib")
        scaler_path = os.path.join(models_dir, "scaler.joblib")
        features_path = os.path.join(models_dir, "feature_names.json")

        if os.path.exists(model_path):
            try:
                import joblib
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path) if os.path.exists(scaler_path) else None
                if os.path.exists(features_path):
                    with open(features_path) as f:
                        self.feature_names = json.load(f)
                self.use_xgboost = True

                # Flow aggregator'ı başlat — akış tamamlandığında _on_flow çağrılır
                self.flow_aggregator = FlowAggregator(
                    window_sec=3.0,
                    on_flow=self._on_flow
                )
                n_feat = len(self.feature_names) if self.feature_names else "?"
                print(f"[DETECTOR] XGBoost modeli yüklendi ({n_feat} öznitelik)")
                print(f"[DETECTOR] Hibrit mod: kural tabanlı (anlık) + XGBoost (akış-bazlı)")
            except Exception as e:
                print(f"[DETECTOR] Model yüklenemedi ({e}) — sadece kural tabanlı.")
        else:
            print(f"[DETECTOR] Model bulunamadı ({model_path}) — sadece kural tabanlı.")

        if not self.use_xgboost:
            print("[DETECTOR] Kural tabanlı tespit aktif.")

    def detect_packet(self, f: FlowFeatures) -> Optional[Detection]:
        """
        Paket-bazlı tespit (Katman 1: kurallar).
        Ayrıca paketi flow aggregator'a ekler (Katman 2 için).

        Returns:
            Detection if rule triggered, None otherwise
        """
        # Paketi akış toplayıcıya ekle (XGBoost için)
        if self.flow_aggregator:
            self.flow_aggregator.add_packet(f)

        # Kural tabanlı tespit
        return self._rule_based(f)

    def get_flow_detections(self) -> list[Detection]:
        """Bekleyen XGBoost akış tespitlerini al ve temizle."""
        dets = list(self._pending_detections)
        self._pending_detections.clear()
        return dets

    def _on_flow(self, feature_vec: np.ndarray, state: FlowState):
        """Flow aggregator callback — akış tamamlandığında XGBoost ile sınıflandır."""
        start = time.perf_counter()

        try:
            # Ölçekle
            vec = feature_vec.reshape(1, -1)
            if self.scaler:
                vec = self.scaler.transform(vec)

            # Tahmin
            proba = self.model.predict_proba(vec)[0]
            is_anomaly = proba[1] > 0.5
            score = int(proba[1] * 100)
            elapsed = (time.perf_counter() - start) * 1000

            det = Detection(
                label="ANOMALY" if is_anomaly else "NORMAL",
                attack_type="ML_Detected" if is_anomaly else "BENIGN",
                threat_score=score,
                confidence=round(float(max(proba)), 3),
                method="xgboost",
                inference_ms=round(elapsed, 3),
                flow_src=state.src_ip,
                flow_dst=state.dst_ip,
                flow_packets=len(state.packet_sizes),
            )

            self._pending_detections.append(det)

            if is_anomaly:
                print(f"[XGBoost] ANOMALY {state.src_ip}→{state.dst_ip} "
                      f"score={score} conf={det.confidence} "
                      f"pkts={det.flow_packets} ({elapsed:.1f}ms)")
            else:
                # Normal akışları da logla (daha az sıklıkla)
                if len(state.packet_sizes) > 10:
                    print(f"[XGBoost] NORMAL  {state.src_ip}→{state.dst_ip} "
                          f"score={score} pkts={det.flow_packets} ({elapsed:.1f}ms)")

        except Exception as e:
            print(f"[XGBoost] Tahmin hatası: {e}")

    def _rule_based(self, f: FlowFeatures) -> Optional[Detection]:
        """Katman 1: bilinen saldırı imzaları."""

        # Port Scan
        if f.unique_ports_last_sec >= 15:
            d = Detection("ANOMALY", "PortScan",
                          min(60 + f.unique_ports_last_sec, 95),
                          0.92, "rule", 0)
            print(f"[RULE] PortScan {f.source_ip}→{f.destination_ip} "
                  f"ports={f.unique_ports_last_sec}")
            return d

        # SYN Flood
        if f.syn_count_last_sec >= 30:
            d = Detection("ANOMALY", "SYN_Flood",
                          min(70 + f.syn_count_last_sec // 5, 99),
                          0.95, "rule", 0)
            print(f"[RULE] SYN_Flood {f.source_ip}→{f.destination_ip} "
                  f"syns={f.syn_count_last_sec}")
            return d

        # Genel flood
        if f.packets_last_sec >= 100:
            d = Detection("ANOMALY", "DoS_Flood",
                          min(65 + f.packets_last_sec // 20, 98),
                          0.88, "rule", 0)
            print(f"[RULE] DoS_Flood {f.source_ip}→{f.destination_ip} "
                  f"pps={f.packets_last_sec}")
            return d

        # Brute force (SSH/FTP)
        if f.dst_port in (22, 21) and f.packets_last_sec >= 20:
            d = Detection("ANOMALY", "BruteForce",
                          min(60 + f.packets_last_sec, 95),
                          0.85, "rule", 0)
            print(f"[RULE] BruteForce {f.source_ip}→{f.destination_ip}:{f.dst_port} "
                  f"pps={f.packets_last_sec}")
            return d

        return None
