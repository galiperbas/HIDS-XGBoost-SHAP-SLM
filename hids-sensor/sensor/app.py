"""
app.py — HIDS ana uygulaması.

Canlı sniffer + detector + WebSocket yayını.
Dashboard (cybercore-command frontend) buraya bağlanır.

Çalıştırma (Windows host, yönetici PowerShell):
  python app.py --iface "Ethernet"

Arayüz adını bulmak için:
  python sensor/sniffer.py    (arayüzleri listeler)
"""

import argparse
import asyncio
import json
import threading
import time
from collections import deque
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

try:
    from .sniffer import LiveSniffer, FlowFeatures
    from .detector import AnomalyDetector
except ImportError:
    from sniffer import LiveSniffer, FlowFeatures
    from detector import AnomalyDetector

# ── App ──
app = FastAPI(title="HIDS Sensor API")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

# ── State ──
clients: set[WebSocket] = set()
recent_logs: deque = deque(maxlen=50)
event_queue: "queue.Queue" = None  # main'de doldurulur

import queue
event_queue = queue.Queue(maxsize=2000)

kpi = {"total": 0, "anomaly": 0, "normal": 0, "critical": 0, "start": time.time()}
traffic_windows: deque = deque(maxlen=20)
_win = {"inbound": 0, "outbound": 0, "time": ""}

detector = AnomalyDetector()  # XGBoost eklemek için: model_path="model.joblib"


def status_from_score(s: int) -> str:
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


# ── Sniffer'ı ayrı thread'de çalıştır, event_queue'ya bas ──
def sniffer_thread(iface):
    # yalnızca bu iki IP'ye gelen/giden trafiği yakala (iki VM var)
    sniffer = LiveSniffer(iface=iface, bpf_filter="host 192.168.238.100 or host 192.168.238.200")

    def on_packet(f: FlowFeatures):
        det = detector.detect(f)
        try:
            event_queue.put_nowait((f, det))
        except queue.Full:
            pass

    sniffer.start(on_packet)


# ── Async tüketici: queue'dan al, işle, yayınla ──
async def consumer_loop():
    global _win
    last_win = time.time()

    while True:
        try:
            f, det = event_queue.get_nowait()
        except queue.Empty:
            await asyncio.sleep(0.05)
            continue

        kpi["total"] += 1
        if det.label == "ANOMALY":
            kpi["anomaly"] += 1
            if det.threat_score >= 70:
                kpi["critical"] += 1
        else:
            kpi["normal"] += 1

        # Trafik penceresi
        if f.src_port > 1024:
            _win["inbound"] += f.packet_size
        else:
            _win["outbound"] += f.packet_size

        now = time.time()
        if now - last_win >= 3:
            _win["time"] = datetime.now().strftime("%H:%M:%S")
            traffic_windows.append(dict(_win))
            _win = {"inbound": 0, "outbound": 0, "time": ""}
            last_win = now
            await broadcast({"type": "traffic", "data": list(traffic_windows)})

        log = {
            "id": str(kpi["total"]),
            "timestamp": f.timestamp,
            "source_ip": f.source_ip,
            "destination_ip": f.destination_ip,
            "protocol": f.protocol,
            "threat_score": det.threat_score,
            "status": status_from_score(det.threat_score),
            "label": det.label,
            "attack_type": det.attack_type,
            "method": det.method,
        }
        recent_logs.appendleft(log)

        if det.label == "ANOMALY" or kpi["total"] % 10 == 0:
            await broadcast({"type": "log", "data": log})

        if kpi["total"] % 15 == 0:
            elapsed = max(time.time() - kpi["start"], 1)
            await broadcast({"type": "kpi", "data": {
                "total_traffic": round(kpi["total"] / elapsed, 2),
                "total_packets": kpi["total"],
                "anomaly_count": kpi["anomaly"],
                "normal_count": kpi["normal"],
                "critical_count": kpi["critical"],
                "uptime_seconds": int(elapsed),
            }})


@app.on_event("startup")
async def startup():
    asyncio.create_task(consumer_loop())


@app.get("/")
async def root():
    return {"service": "HIDS Sensor", "status": "online",
            "detector": "xgboost" if detector.use_xgboost else "rule-based",
            "packets": kpi["total"]}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    clients.add(ws)
    try:
        await ws.send_text(json.dumps({"type": "logs_init", "data": list(recent_logs)}))
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        clients.discard(ws)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", default=None, help="Ağ arayüzü adı (boşsa varsayılan)")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    # Sniffer thread'i başlat
    t = threading.Thread(target=sniffer_thread, args=(args.iface,), daemon=True)
    t.start()

    print(f"[HIDS] Sensor başlatıldı. Dashboard WS: ws://localhost:{args.port}/ws")
    uvicorn.run(app, host="0.0.0.0", port=args.port)
