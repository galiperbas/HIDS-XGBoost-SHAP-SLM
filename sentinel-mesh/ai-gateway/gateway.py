"""
gateway.py — Sentinel Mesh AI Gateway (LLM Firewall / reverse proxy).

MİMARİ ROLÜ — "şifreli trafik" sorusunun cevabı:
  Ağ sensörü (Pi) L3/L4 başlıklarını görür ama TLS payload'unu GÖREMEZ.
  Bu gateway, AI servisinin ÖNÜNDE durur: TLS burada sonlanır, prompt PLAINTEXT
  olarak görülür, denetlenir, sonra upstream'e iletilir. Gerçek LLM firewall'ların
  (Cloudflare AI Gateway, Lakera, Prompt Guard) production'da durduğu yer burasıdır.

  [Kullanıcı] --TLS--> [BU GATEWAY: promptguard + analyst] --> [AI/LLM servisi]
                              |
                              +--push--> [Sentinel Mesh Relay /ingest] --> Dashboard

Akış:
  1. İstemi (prompt) al.
  2. promptguard.analyze() ile denetle (OWASP LLM Top 10, açıklanabilir skor).
  3. BLOCK ise: isteği reddet, olayı relay'e push et, analyst triyajını ekle.
     ALLOW ise: upstream AI servisine ilet (varsa), normal telemetri push et.

Çalıştırma:
  pip install -r requirements.txt
  export RELAY_URL="wss://hids-xgboost-shap-slm.onrender.com/ingest"
  export UPSTREAM_AI_URL="http://127.0.0.1:9000/chat"   # gerçek AI servisi (ops.)
  export ANTHROPIC_API_KEY="..."                          # analyst için (ops.)
  uvicorn gateway:app --host 0.0.0.0 --port 8088
"""

from __future__ import annotations

import json
import os
import ssl
import threading
import queue
import time
from datetime import datetime

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import promptguard
import analyst

try:
    import websocket  # websocket-client
except ImportError:
    websocket = None


# ── Konfigürasyon (ortam değişkenleri) ──
RELAY_URL = os.environ.get("RELAY_URL", "wss://hids-xgboost-shap-slm.onrender.com/ingest")
UPSTREAM_AI_URL = os.environ.get("UPSTREAM_AI_URL", "")  # boşsa stub yanıt döner
BLOCK_THRESHOLD = int(os.environ.get("BLOCK_THRESHOLD", "60"))
FLAG_THRESHOLD = int(os.environ.get("FLAG_THRESHOLD", "30"))
ANALYST_ON = os.environ.get("ANALYST_ON_BLOCK", "true").lower() == "true"
SELF_IP = os.environ.get("GATEWAY_IP", "ai-gateway")


app = FastAPI(title="Sentinel Mesh — AI Gateway (LLM Firewall)")


# ──────────────────────────────────────────────────────────────────────────
#  Relay push istemcisi — Pi sensörüyle aynı /ingest kanalını kullanır.
#  Gateway, relay'e başka bir "sensör" gibi bağlanır; dashboard olayları render eder.
# ──────────────────────────────────────────────────────────────────────────
class RelayPusher:
    def __init__(self, url: str):
        self.url = url
        self._q: queue.Queue = queue.Queue(maxsize=2000)
        self._ws = None
        self.connected = False
        self._running = False

    def start(self):
        if websocket is None:
            print("[GATEWAY] websocket-client yok — relay push devre dışı.")
            return
        self._running = True
        threading.Thread(target=self._loop, daemon=True).start()
        print(f"[GATEWAY] Relay push başlatıldı → {self.url}")

    def push(self, event: dict):
        try:
            self._q.put_nowait(event)
        except queue.Full:
            pass

    def _loop(self):
        while self._running:
            try:
                sslopt = {"cert_reqs": ssl.CERT_NONE} if self.url.startswith("wss://") else None
                self._ws = websocket.create_connection(self.url, timeout=10, sslopt=sslopt)
                self.connected = True
                print(f"[GATEWAY] Relay'e bağlandı: {self.url}")
                while self._running:
                    try:
                        ev = self._q.get(timeout=1.0)
                        self._ws.send(json.dumps(ev))
                    except queue.Empty:
                        try:
                            self._ws.ping()
                        except Exception:
                            break
            except Exception as e:
                self.connected = False
                print(f"[GATEWAY] Relay bağlantı hatası ({e}); 5s sonra yeniden.")
                time.sleep(5)


pusher = RelayPusher(RELAY_URL)

# Basit istatistik
stats = {"total": 0, "blocked": 0, "flagged": 0, "allowed": 0}


def _extract_prompt(body: dict) -> str:
    """Farklı API şekillerinden prompt metnini çıkar (OpenAI-uyumlu dahil)."""
    if not isinstance(body, dict):
        return str(body or "")
    if isinstance(body.get("prompt"), str):
        return body["prompt"]
    if isinstance(body.get("input"), str):
        return body["input"]
    msgs = body.get("messages")
    if isinstance(msgs, list):
        parts = []
        for m in msgs:
            c = m.get("content") if isinstance(m, dict) else None
            if isinstance(c, str):
                parts.append(c)
            elif isinstance(c, list):  # içerik blokları
                parts += [b.get("text", "") for b in c if isinstance(b, dict)]
        return "\n".join(p for p in parts if p)
    return ""


def _make_event(guard: promptguard.GuardResult, src_ip: str) -> dict:
    """promptguard sonucundan dashboard-uyumlu olay üret."""
    return {
        "id": str(stats["total"]),
        "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "source_ip": src_ip,
        "destination_ip": SELF_IP,
        "protocol": "AI-API",
        "threat_score": guard.score,
        "status": "CRITICAL" if guard.score >= 70 else "MEDIUM" if guard.score >= 35 else "SAFE",
        "label": "ANOMALY" if guard.is_malicious else "NORMAL",
        "attack_type": guard.attack_type,
        "method": "promptguard",
        "owasp": guard.owasp,
        "reasons": guard.reasons(),
    }


async def _forward_upstream(body: dict) -> dict:
    """İsteği gerçek AI servisine ilet. UPSTREAM yoksa stub yanıt döndür."""
    if not UPSTREAM_AI_URL:
        return {"role": "assistant",
                "content": "[stub] AI servisi yapılandırılmadı; istek güvenlik denetiminden geçti."}
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(UPSTREAM_AI_URL, json=body)
        try:
            return r.json()
        except Exception:
            return {"content": r.text}


@app.post("/v1/chat")
@app.post("/chat")
@app.post("/")
async def chat(request: Request):
    """AI servis isteklerinin geçtiği denetim noktası."""
    try:
        body = await request.json()
    except Exception:
        body = {}

    src_ip = (request.client.host if request.client else "?")
    prompt = _extract_prompt(body)

    guard = promptguard.analyze(prompt, BLOCK_THRESHOLD, FLAG_THRESHOLD)
    stats["total"] += 1

    event = _make_event(guard, src_ip)

    if guard.verdict == "BLOCK":
        stats["blocked"] += 1
        triage = analyst.analyze(event, guard.to_dict()) if ANALYST_ON else None
        if triage:
            event["analysis"] = triage
        pusher.push(event)
        print(f"[GATEWAY] BLOCK {src_ip} {guard.attack_type} score={guard.score}")
        return JSONResponse(status_code=403, content={
            "blocked": True,
            "reason": f"{guard.owasp} — {guard.attack_type}",
            "score": guard.score,
            "evidence": guard.reasons(),
            "analysis": triage,
        })

    if guard.verdict == "FLAG":
        stats["flagged"] += 1
        pusher.push(event)
        print(f"[GATEWAY] FLAG {src_ip} {guard.attack_type} score={guard.score} (geçişe izin verildi)")

    # ALLOW veya FLAG -> upstream'e ilet
    if guard.verdict == "ALLOW":
        stats["allowed"] += 1
        pusher.push(event)  # normal telemetri (dashboard "NORMAL" sayacı)

    answer = await _forward_upstream(body)
    return {"blocked": False, "score": guard.score, "answer": answer}


@app.get("/health")
async def health():
    return {"status": "ok", "relay_connected": pusher.connected, "stats": stats}


@app.get("/api/stats")
async def api_stats():
    return {"stats": stats, "relay": RELAY_URL, "upstream": UPSTREAM_AI_URL or None,
            "thresholds": {"block": BLOCK_THRESHOLD, "flag": FLAG_THRESHOLD}}


@app.on_event("startup")
async def _startup():
    pusher.start()


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8088"))
    print(f"[GATEWAY] AI Gateway başlıyor :{port}  relay={RELAY_URL}")
    uvicorn.run(app, host="0.0.0.0", port=port)
