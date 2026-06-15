"""
relay_server.py — HIDS Bulut Relay Sunucusu.

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
import os
import random
import time
import asyncio
from collections import deque
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

try:
    from simulator import generate_event
except ImportError:
    generate_event = None

app = FastAPI(title="HIDS Relay")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

# Yazma uçlarını koruyan basit paylaşımlı anahtar (env'den).
# Ayarlanmazsa (boş) eski davranış sürer; üretimde Render env'inde tanımlayın.
INGEST_TOKEN = os.environ.get("INGEST_TOKEN", "")


def _token_ok(provided: str) -> bool:
    """Token tanımlı değilse herkese izin ver; tanımlıysa eşleşme şart."""
    return (not INGEST_TOKEN) or (provided == INGEST_TOKEN)

# Statik dosya servisi (web dashboard)
STATIC_DIR = Path(__file__).parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

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

# Demo modu (Pi bağlı değilken yedek veri üretimi)
DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() == "true"
demo_event_id = 0


def _is_demo() -> bool:
    """Şu an gösterilen veri simüle mi? (DEMO açık ve gerçek sensör yokken)."""
    return DEMO_MODE and sensor_count == 0

# ── Gemini chatbot (ev kullanıcısı için güvenlik asistanı) ──
# API anahtarı yalnızca sunucu tarafında env değişkeninde tutulur — tarayıcıya
# ve koda ASLA gömülmez. Render → Environment → GEMINI_API_KEY olarak ayarlanır.
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
# NOT: gemini-2.0-flash Google tarafından KAPATILDI (404 verir). Güncel GA flash:
# gemini-2.5-flash (hızlı/ucuz) ve gemini-3.5-flash.
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
# Birincil model 404 verirse (model kapatılmışsa) sırayla denenecek güncel yedekler
GEMINI_FALLBACKS = ["gemini-2.5-flash", "gemini-3.5-flash", "gemini-flash-latest"]
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

CHAT_SYSTEM = """Sen bir ev ağı güvenlik asistanısın. Evdeki internet ağını \
koruyan bir cihazın (Raspberry Pi sensörü) tespit ettiği durumları, TEKNİK BİLGİSİ OLMAYAN \
bir ev kullanıcısına sade, sakin ve güven veren bir dille TÜRKÇE açıklarsın.

Kurallar:
- Jargon kullanma; kullanman gerekirse hemen günlük dille açıkla (örn. "port tarama = biri \
evinin tüm kapı ve pencerelerini tek tek deneyip açık var mı diye bakıyor gibi").
- Kısa ve net ol (2-5 cümle). Gerekirse "Ne yapmalıyım?" için kısa maddeler ver.
- Panik yaratma; durumu olduğu gibi ama sakin anlat. Abartma, küçümseme.
- SADECE aşağıdaki canlı ağ durumuna ve kullanıcının sorusuna dayan. Veri yoksa veya saldırı \
yoksa "Şu an ağında olağandışı bir şey görünmüyor, her şey normal." de.
- Ağ/ev güvenliği dışındaki konularda kibarca konuyu güvenliğe getir.
- Emoji'yi çok az ve yerinde kullan.

GÜNCEL AĞ DURUMU:
{context}"""


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


async def demo_loop():
    """Demo modu: Pi bağlı değilken sahte veri üret."""
    global demo_event_id
    if not DEMO_MODE or generate_event is None:
        return
    print("[DEMO] Demo modu aktif — Pi bağlanınca otomatik durur.")

    await asyncio.sleep(3)  # Başlangıçta bekle

    while True:
        # Pi bağlıysa demo durur
        if sensor_count > 0:
            await asyncio.sleep(5)
            continue

        demo_event_id += 1
        event = generate_event(demo_event_id)

        # İstatistik güncelle
        stats["total_events"] += 1
        label = event.get("label", "NORMAL")
        attack_type = event.get("attack_type", "BENIGN")
        score = event.get("threat_score", 0)

        if label == "ANOMALY":
            stats["anomaly_count"] += 1
            if score >= 70:
                stats["critical_count"] += 1
            attack_distribution[attack_type] = attack_distribution.get(attack_type, 0) + 1
        else:
            stats["normal_count"] += 1

        from datetime import datetime
        event["server_time"] = datetime.now().strftime("%H:%M:%S")
        log_history.appendleft(event)

        # Mobile/web client'lara yayınla
        await broadcast_to_mobile({"type": "event", "data": event})

        if label == "ANOMALY" and score >= 70:
            await broadcast_to_mobile({
                "type": "alert",
                "title": f"⚠️ {attack_type} Saldırısı!",
                "body": f"{event.get('source_ip','?')} → {event.get('destination_ip','?')} (tehdit: {score})",
                "data": event,
            })

        # Rastgele aralık (2-6 saniye)
        await asyncio.sleep(random.uniform(2, 6))


@app.get("/")
async def root():
    """Web dashboard veya API status."""
    # HTML istiyorsa dashboard, değilse JSON
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    # Fallback: JSON status
    uptime = int(time.time() - stats["server_start"])
    return {
        "service": "HIDS Relay",
        "status": "online",
        "sensors_online": stats["sensors_online"],
        "mobile_clients": len(mobile_clients),
        "total_events": stats["total_events"],
        "anomaly_count": stats["anomaly_count"],
        "uptime_seconds": uptime,
    }


@app.get("/api/status")
async def api_status():
    """JSON status (dashboard olmadan)."""
    uptime = int(time.time() - stats["server_start"])
    return {
        "service": "HIDS Relay",
        "status": "online",
        "demo_mode": DEMO_MODE and sensor_count == 0,
        "sensors_online": stats["sensors_online"],
        "mobile_clients": len(mobile_clients),
        "total_events": stats["total_events"],
        "anomaly_count": stats["anomaly_count"],
        "uptime_seconds": uptime,
    }

@app.get("/api/events")
async def api_events():
    """Son 50 olay."""
    return {"events": list(log_history)[:50]}

@app.get("/api/stats")
async def api_stats():
    """İstatistik özeti."""
    uptime = int(time.time() - stats["server_start"])
    return {
        "stats": stats,
        "uptime_seconds": uptime,
        "attack_distribution": attack_distribution,
        "demo_mode": DEMO_MODE and sensor_count == 0,
    }

@app.post("/api/reset")
async def api_reset():
    """Tüm istatistikleri ve log geçmişini sıfırlar."""
    global attack_distribution, log_history
    stats["total_events"] = 0
    stats["anomaly_count"] = 0
    stats["critical_count"] = 0
    stats["normal_count"] = 0
    attack_distribution.clear()
    log_history.clear()
    
    # Tüm bağlı dashboard istemcilerine sıfırlama sinyali gönder
    await broadcast_to_mobile({
        "type": "reset",
        "stats": stats,
        "attack_distribution": attack_distribution,
        "recent_logs": []
    })
    print("[RESET] Tüm istatistikler ve loglar sıfırlandı.")
    return {"status": "ok"}


@app.get("/api/health")
async def health():
    """Render health check & keep-alive."""
    return {"status": "ok", "timestamp": time.time()}

@app.get("/api/summary")
async def summary():
    """Mobil app açılışta özet çeker."""
    uptime = int(time.time() - stats["server_start"])
    return {
        "stats": stats,
        "uptime_seconds": uptime,
        "attack_distribution": attack_distribution,
        "recent_logs": list(log_history)[:50],
        "demo_mode": _is_demo(),
    }


def _security_context() -> str:
    """Chatbot'a verilecek canlı ağ durumu özeti (Türkçe, sade)."""
    lines = [
        f"- Bağlı sensör sayısı: {stats['sensors_online']}",
        f"- Toplam olay: {stats['total_events']}, "
        f"anomali (şüpheli): {stats['anomaly_count']}, "
        f"kritik: {stats['critical_count']}, normal: {stats['normal_count']}",
    ]
    if attack_distribution:
        top = sorted(attack_distribution.items(), key=lambda x: -x[1])[:5]
        lines.append("- Tespit edilen saldırı türleri: "
                     + ", ".join(f"{k} ({v} kez)" for k, v in top))
    else:
        lines.append("- Henüz herhangi bir saldırı tespit edilmedi.")

    recent = list(log_history)[:5]
    if recent:
        lines.append("- Son olaylar:")
        for e in recent:
            line = (f"    • {e.get('server_time', '')} {e.get('attack_type', '?')} "
                    f"kaynak {e.get('source_ip', '?')} → hedef {e.get('destination_ip', '?')} "
                    f"(tehdit skoru {e.get('threat_score', 0)}/100)")
            # Açıklanabilirlik: modeli en çok etkileyen öznitelikler (varsa)
            shap_top = e.get("shap_top") or []
            if shap_top:
                feats = ", ".join(s.get("feature", "") for s in shap_top[:3])
                line += f" — kararı en çok etkileyen göstergeler: {feats}"
            lines.append(line)
    return "\n".join(lines)


@app.post("/api/chat")
async def chat(payload: dict):
    """
    Ev kullanıcısı güvenlik asistanı (Gemini).
    API anahtarı sunucu tarafında kalır; tarayıcı yalnızca bu uç noktayla konuşur.
    """
    message = (payload.get("message") or "").strip()
    history = payload.get("history") or []

    if not message:
        return {"reply": "Bir soru yazabilirsiniz. Örn: \"Ağımda tehlike var mı?\""}
    if not GEMINI_API_KEY:
        return {"reply": "Asistan henüz yapılandırılmadı (sunucuda API anahtarı tanımlı değil)."}

    try:
        import httpx
    except ImportError:
        return {"reply": "Asistan bileşeni sunucuda yüklü değil (httpx eksik)."}

    system = CHAT_SYSTEM.format(context=_security_context())

    # Sohbet geçmişini Gemini formatına çevir (rol: user / model)
    contents = []
    for h in history[-10:]:
        role = "model" if h.get("role") in ("bot", "model", "assistant") else "user"
        txt = (h.get("text") or "").strip()
        if txt:
            contents.append({"role": role, "parts": [{"text": txt}]})
    contents.append({"role": "user", "parts": [{"text": message}]})

    body = {
        "system_instruction": {"parts": [{"text": system}]},
        "contents": contents,
        "generationConfig": {"temperature": 0.4, "maxOutputTokens": 800},
    }

    # Denenecek modeller: önce yapılandırılan, sonra güncel yedekler (404'a karşı)
    models_to_try = []
    for m in [GEMINI_MODEL] + GEMINI_FALLBACKS:
        if m and m not in models_to_try:
            models_to_try.append(m)

    try:
        async with httpx.AsyncClient(timeout=25) as client:
            for model in models_to_try:
                url = GEMINI_URL.format(model=model)
                r = await client.post(url, params={"key": GEMINI_API_KEY}, json=body)

                # Model kapatılmış/bulunamadı → bir sonraki yedeği dene
                if r.status_code == 404:
                    print(f"[CHAT] model 404 (kapalı olabilir): {model} → yedeğe geçiliyor")
                    continue

                data = r.json()
                if r.status_code != 200:
                    print(f"[CHAT] Gemini hatası {r.status_code} ({model}): {str(data)[:200]}")
                    return {"reply": "Şu an asistana ulaşamadım, birazdan tekrar deneyin."}

                candidates = data.get("candidates") or []
                if not candidates:
                    # İçerik güvenlik filtresine takılmış olabilir
                    return {"reply": "Bu soruya şu an yanıt veremedim. Farklı bir şekilde sorabilir misiniz?"}
                parts = candidates[0].get("content", {}).get("parts", [])
                reply = "".join(p.get("text", "") for p in parts).strip()
                print(f"[CHAT] yanıt verildi (model={model})")
                return {"reply": reply or "Şu an net bir yanıt oluşturamadım."}

        # Tüm modeller 404 verdi
        print(f"[CHAT] tüm modeller 404: {models_to_try}")
        return {"reply": "Asistan modeline ulaşılamadı. Model adı güncel olmayabilir."}
    except Exception as e:
        print(f"[CHAT] istisna: {e}")
        return {"reply": "Bağlantı sorunu oldu, lütfen tekrar deneyin."}


@app.websocket("/ingest")
async def ingest(ws: WebSocket):
    """
    Raspberry Pi HIDS sensörü buraya bağlanır ve log push eder.
    Pi outbound bağlantı açar — Pi'de açık port YOK (güvenli).

    INGEST_TOKEN ayarlıysa, Pi URL'ine ?token=... eklemek zorunludur
    (örn. wss://.../ingest?token=XYZ). Böylece yabancılar sahte olay enjekte edemez.
    """
    global sensor_count
    if not _token_ok(ws.query_params.get("token", "")):
        await ws.close(code=1008)  # policy violation
        print("[INGEST] Reddedildi: geçersiz/eksik token.")
        return
    await ws.accept()
    sensor_count += 1
    stats["sensors_online"] = sensor_count
    print(f"[INGEST] Sensör bağlandı. Aktif sensör: {sensor_count}")

    # Mobile'a sensör durumunu bildir
    await broadcast_to_mobile({
        "type": "sensor_status",
        "online": sensor_count,
        "demo_mode": _is_demo(),
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
            "demo_mode": _is_demo(),
        }))
        while True:
            await ws.receive_text()  # ping/keepalive
    except WebSocketDisconnect:
        mobile_clients.discard(ws)
        print(f"[STREAM] Mobil client ayrıldı. Toplam: {len(mobile_clients)}")


@app.on_event("startup")
async def startup():
    asyncio.create_task(demo_loop())
