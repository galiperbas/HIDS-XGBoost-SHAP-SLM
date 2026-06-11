"""
relay_server.py — Sentinel Mesh Bulut Relay Sunucusu.

Mimari:
  [Raspberry Pi HIDS] --push--> [BU SUNUCU] --broadcast--> [Flutter Mobil App]

İki ayrı WebSocket kanalı:
  /ingest  — Pi'ler buraya log push eder (telemetry girişi)
  /stream  — Mobil app'ler buradan canlı veri alır (dashboard çıkışı)

Pi yalnızca outbound bağlantı açar (güvenli: Pi'de açık port yok).
Mobil app de yalnızca outbound bağlantı açar.
Sunucu ortada durur, ikisini köprüler ve log geçmişini saklar.

Çalıştırma:
  uvicorn relay_server:app --host 0.0.0.0 --port 9000
"""

import json
import time
from collections import deque
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Sentinel Mesh Relay")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

# ── State ──
mobile_clients: set[WebSocket] = set()   # Dashboard izleyiciler
sensor_count = 0                          # Bağlı Pi sayısı
log_history: deque = deque(maxlen=200)    # Son 200 olay
stats = {
    "total_events": 0,
    "anomaly_count": 0,
    "critical_count": 0,
    "normal_count": 0,
    "sensors_online": 0,
    "server_start": time.time(),
}
# Saldırı türü dağılımı (dashboard grafiği için)
attack_distribution: dict[str, int] = {}


async def broadcast_to_mobile(message: dict):
    """Tüm mobil dashboard'lara mesaj gönder."""
    dead = set()
    payload = json.dumps(message)
    for ws in mobile_clients:
        try:
            await ws.send_text(payload)
        except Exception:
            dead.add(ws)
    mobile_clients.difference_update(dead)


@app.get("/")
async def root():
    uptime = int(time.time() - stats["server_start"])
    return {
        "service": "Sentinel Mesh Relay",
        "status": "online",
        "sensors_online": stats["sensors_online"],
        "mobile_clients": len(mobile_clients),
        "total_events": stats["total_events"],
        "anomaly_count": stats["anomaly_count"],
        "uptime_seconds": uptime,
    }


@app.get("/api/summary")
async def summary():
    """Mobil app açılışta özet çeker."""
    uptime = int(time.time() - stats["server_start"])
    return {
        "stats": stats,
        "uptime_seconds": uptime,
        "attack_distribution": attack_distribution,
        "recent_logs": list(log_history)[:50],
    }


@app.websocket("/ingest")
async def ingest(ws: WebSocket):
    """
    Raspberry Pi HIDS sensörü buraya bağlanır ve log push eder.
    Pi outbound bağlantı açar — Pi'de açık port YOK (güvenli).
    """
    global sensor_count
    await ws.accept()
    sensor_count += 1
    stats["sensors_online"] = sensor_count
    print(f"[INGEST] Sensör bağlandı. Aktif sensör: {sensor_count}")

    # Mobile'a sensör durumunu bildir
    await broadcast_to_mobile({
        "type": "sensor_status",
        "online": sensor_count,
    })

    try:
        while True:
            raw = await ws.receive_text()
            event = json.loads(raw)

            # İstatistik güncelle
            stats["total_events"] += 1
            label = event.get("label", "NORMAL")
            attack_type = event.get("attack_type", "BENIGN")
            score = event.get("threat_score", 0)

            if label == "ANOMALY":
                stats["anomaly_count"] += 1
                if score >= 70:
                    stats["critical_count"] += 1
                # Saldırı dağılımı
                attack_distribution[attack_type] = \
                    attack_distribution.get(attack_type, 0) + 1
            else:
                stats["normal_count"] += 1

            # Geçmişe ekle
            event["server_time"] = datetime.now().strftime("%H:%M:%S")
            log_history.appendleft(event)

            # Mobile'a canlı yayınla
            await broadcast_to_mobile({"type": "event", "data": event})

            # Kritik saldırıda bildirim tetikle
            if label == "ANOMALY" and score >= 70:
                await broadcast_to_mobile({
                    "type": "alert",
                    "title": f"⚠️ {attack_type} Saldırısı!",
                    "body": f"{event.get('source_ip','?')} → "
                            f"{event.get('destination_ip','?')} "
                            f"(tehdit: {score})",
                    "data": event,
                })

    except WebSocketDisconnect:
        sensor_count -= 1
        stats["sensors_online"] = sensor_count
        print(f"[INGEST] Sensör ayrıldı. Aktif sensör: {sensor_count}")
        await broadcast_to_mobile({
            "type": "sensor_status",
            "online": sensor_count,
        })


@app.websocket("/stream")
async def stream(ws: WebSocket):
    """
    Flutter mobil app buraya bağlanır, canlı veri alır.
    """
    await ws.accept()
    mobile_clients.add(ws)
    print(f"[STREAM] Mobil client bağlandı. Toplam: {len(mobile_clients)}")

    try:
        # Açılışta mevcut durumu gönder
        await ws.send_text(json.dumps({
            "type": "init",
            "stats": stats,
            "attack_distribution": attack_distribution,
            "recent_logs": list(log_history)[:50],
        }))
        while True:
            await ws.receive_text()  # ping/keepalive
    except WebSocketDisconnect:
        mobile_clients.discard(ws)
        print(f"[STREAM] Mobil client ayrıldı. Toplam: {len(mobile_clients)}")
