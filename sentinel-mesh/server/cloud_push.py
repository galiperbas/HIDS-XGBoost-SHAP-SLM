"""
cloud_push.py — HIDS sensöründen bulut relay sunucusuna log push eder.

Güvenlik tasarımı: Pi YALNIZCA outbound bağlantı açar.
Pi'de hiçbir port dinlenmez → Pi'nin saldırı yüzeyi minimum.
Bağlantı koparsa otomatik yeniden bağlanır, log kuyruğa alınır.

app.py içinde kullanımı:
    from cloud_push import CloudPusher
    pusher = CloudPusher("ws://SUNUCU_IP:9000/ingest")
    pusher.start()
    # tespit olduğunda:
    pusher.push(log_dict)
"""

import json
import queue
import threading
import time

try:
    import websocket  # websocket-client paketi
except ImportError:
    websocket = None


class CloudPusher:
    """Logları bulut relay'e push eden, otomatik yeniden bağlanan client."""

    def __init__(self, url: str, reconnect_delay: float = 5.0):
        self.url = url
        self.reconnect_delay = reconnect_delay
        self._queue: queue.Queue = queue.Queue(maxsize=5000)
        self._ws = None
        self._connected = False
        self._running = False

        if websocket is None:
            print("[CLOUD] websocket-client kurulu değil. "
                  "Kurulum: pip install websocket-client")

    def start(self):
        """Push thread'ini başlat."""
        if websocket is None:
            print("[CLOUD] Push devre dışı (websocket-client yok).")
            return
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()
        print(f"[CLOUD] Push client başlatıldı → {self.url}")

    def push(self, event: dict):
        """Bir olayı kuyruğa ekle (non-blocking)."""
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            pass  # Kuyruk doluysa en eskiyi kaybet

    def _loop(self):
        """Bağlan, kuyruktaki olayları gönder, koparsa yeniden bağlan."""
        while self._running:
            try:
                self._ws = websocket.create_connection(
                    self.url, timeout=10)
                self._connected = True
                print(f"[CLOUD] Bağlandı: {self.url}")

                while self._running:
                    try:
                        event = self._queue.get(timeout=1.0)
                        self._ws.send(json.dumps(event))
                    except queue.Empty:
                        # Keepalive
                        try:
                            self._ws.ping()
                        except Exception:
                            break
            except Exception as e:
                self._connected = False
                print(f"[CLOUD] Bağlantı hatası ({e}). "
                      f"{self.reconnect_delay}s sonra yeniden denenecek.")
                time.sleep(self.reconnect_delay)

    @property
    def connected(self) -> bool:
        return self._connected

    def stop(self):
        self._running = False
        if self._ws:
            try:
                self._ws.close()
            except Exception:
                pass
