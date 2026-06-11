"""
app.py — HIDS ana uygulaması (hibrit tespit).

Katman 1: Kural tabanlı (paket-bazlı, anlık)
Katman 2: XGBoost (akış-bazlı, pencere dolunca)

Çalıştırma (Yönetici PowerShell):
  python sensor\\app.py --iface "VMware Network Adapter VMnet1"
"""

import argparse
import asyncio
import json
import queue
import threading
import time
from collections import deque
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

try:
    from .sniffer import LiveSniffer, FlowFeatures
    from .detector import AnomalyDetector, Detection
except ImportError:
    from sniffer import LiveSniffer, FlowFeatures
    from detector import AnomalyDetector, Detection

# ── App ──
app = FastAPI(title="HIDS Sensor API — Hybrid Detection")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

# ── State ──
clients: set[WebSocket] = set()
recent_logs: deque = deque(maxlen=100)
event_queue: queue.Queue = queue.Queue(maxsize=5000)

kpi = {"total": 0, "anomaly": 0, "normal": 0, "critical": 0,
       "rule_detections": 0, "xgboost_detections": 0, "start": time.time()}
traffic_windows: deque = deque(maxlen=30)
_win = {"inbound": 0, "outbound": 0, "time": ""}

# models/ dizininden XGBoost modeli yükle (varsa)
detector = AnomalyDetector(models_dir="models")


def status_label(s: int) -> str:
    return "CRITICAL" if s >= 70 else "MEDIUM" if s >= 35 else "SAFE"


async def broadcast(msg: dict):
    dead = set()
    payload = json.dumps(msg)
    for ws in clients:
        try:
            await ws.send_text(payload)
        except Exception:
            dead.add(ws)
    clients.difference_update(dead)


def make_log(det: Detection, src: str = "", dst: str = "",
             proto: str = "", ts: str = "") -> dict:
    return {
        "id": str(kpi["total"]),
        "timestamp": ts or datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "source_ip": det.flow_src or src,
        "destination_ip": det.flow_dst or dst,
        "protocol": proto or det.attack_type,
        "threat_score": det.threat_score,
        "status": status_label(det.threat_score),
        "label": det.label,
        "attack_type": det.attack_type,
        "method": det.method,
        "confidence": det.confidence,
        "flow_packets": det.flow_packets,
    }


# ── Sniffer thread ──
def sniffer_thread(iface, bpf):
    sniffer = LiveSniffer(iface=iface, bpf_filter=bpf)

    def on_packet(f: FlowFeatures):
        rule_det = detector.detect_packet(f)
        try:
            event_queue.put_nowait((f, rule_det))
        except queue.Full:
            pass

    sniffer.start(on_packet)


# ── Async consumer ──
async def consumer_loop():
    global _win
    last_win = time.time()
    last_flow_check = time.time()

    while True:
        processed = 0
        # Paket olaylarını işle (batch)
        while processed < 100:
            try:
                f, rule_det = event_queue.get_nowait()
                processed += 1
            except queue.Empty:
                break

            kpi["total"] += 1

            # Trafik penceresi
            if f.src_port > 1024:
                _win["inbound"] += f.packet_size
            else:
                _win["outbound"] += f.packet_size

            # Kural tabanlı tespit varsa yayınla
            if rule_det and rule_det.label == "ANOMALY":
                kpi["anomaly"] += 1
                kpi["rule_detections"] += 1
                if rule_det.threat_score >= 70:
                    kpi["critical"] += 1
                log = make_log(rule_det, f.source_ip, f.destination_ip,
                               f.protocol, f.timestamp)
                recent_logs.appendleft(log)
                await broadcast({"type": "log", "data": log})
            else:
                kpi["normal"] += 1

        # XGBoost akış tespitlerini kontrol et (her 0.5 saniyede)
        now = time.time()
        if now - last_flow_check >= 0.5:
            last_flow_check = now
            flow_dets = detector.get_flow_detections()
            for det in flow_dets:
                if det.label == "ANOMALY":
                    kpi["anomaly"] += 1
                    kpi["xgboost_detections"] += 1
                    if det.threat_score >= 70:
                        kpi["critical"] += 1
                log = make_log(det)
                recent_logs.appendleft(log)
                await broadcast({"type": "log", "data": log})

        # Trafik penceresi yayını
        if now - last_win >= 3:
            _win["time"] = datetime.now().strftime("%H:%M:%S")
            traffic_windows.append(dict(_win))
            _win = {"inbound": 0, "outbound": 0, "time": ""}
            last_win = now
            await broadcast({"type": "traffic", "data": list(traffic_windows)})

        # KPI yayını
        if kpi["total"] > 0 and kpi["total"] % 20 == 0:
            elapsed = max(time.time() - kpi["start"], 1)
            await broadcast({"type": "kpi", "data": {
                "total_traffic": round(kpi["total"] / elapsed, 2),
                "total_packets": kpi["total"],
                "anomaly_count": kpi["anomaly"],
                "normal_count": kpi["normal"],
                "critical_count": kpi["critical"],
                "rule_detections": kpi["rule_detections"],
                "xgboost_detections": kpi["xgboost_detections"],
                "uptime_seconds": int(elapsed),
            }})

        if processed == 0:
            await asyncio.sleep(0.05)


@app.on_event("startup")
async def startup():
    asyncio.create_task(consumer_loop())


@app.get("/")
async def root():
    elapsed = max(time.time() - kpi["start"], 1)
    return {
        "service": "HIDS Sensor",
        "status": "online",
        "detector": "hybrid (rule + xgboost)" if detector.use_xgboost else "rule-based",
        "packets": kpi["total"],
        "anomalies": kpi["anomaly"],
        "rule_detections": kpi["rule_detections"],
        "xgboost_detections": kpi["xgboost_detections"],
        "uptime": int(elapsed),
    }


@app.get("/api/logs")
async def get_logs():
    return {"logs": list(recent_logs)}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    clients.add(ws)
    print(f"[WS] Client bağlandı. Toplam: {len(clients)}")
    try:
        await ws.send_text(json.dumps({"type": "logs_init", "data": list(recent_logs)}))
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        clients.discard(ws)
        print(f"[WS] Client ayrıldı. Toplam: {len(clients)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HIDS Sensor — Hybrid Detection")
    parser.add_argument("--iface", default=None, help="Ağ arayüzü")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--bpf", default="host 192.168.238.100 or host 192.168.238.200",
                        help="BPF filtre (VM IP'leri)")
    parser.add_argument("--models", default="models", help="Model dizini")
    args = parser.parse_args()

# Model dizinini güncelle
    if args.models != "models":
        detector.__init__(models_dir=args.models)

    # Sniffer thread başlat
    t = threading.Thread(target=sniffer_thread, args=(args.iface, args.bpf), daemon=True)
    t.start()

    print(f"[HIDS] Hibrit sensör başlatıldı.")
    print(f"[HIDS] Dashboard: ws://localhost:{args.port}/ws")
    print(f"[HIDS] BPF: {args.bpf}")
    uvicorn.run(app, host="0.0.0.0", port=args.port)
