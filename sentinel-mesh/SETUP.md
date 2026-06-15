# HIDS — Kurulum ve Çalıştırma Rehberi

Üç parçalı dağıtık mimari: Pi (sensör) → Bulut sunucu (relay) → Mobil app (dashboard).

```
[Raspberry Pi HIDS]  --push-->  [Bulut Relay Sunucu]  --broadcast-->  [Flutter Mobil App]
 outbound only                   /ingest  /stream                      canlı dashboard
 (açık port yok)                 log toplar, bildirim                   + push bildirim
```

## Güvenlik Tasarımı

Pi yalnızca **outbound** WebSocket bağlantısı açar (`/ingest`). Pi'de hiçbir
port dinlenmez. Bu, Pi'nin saldırı yüzeyini sıfıra indirir — internete açık
bir IDS'in kendisinin hedef olması ("zero inbound, push-only telemetry")
önlenir. Mobil app de yalnızca outbound bağlanır (`/stream`). Sunucu ortada
köprü görevi görür.

---

## 1. Bulut Relay Sunucu

Herhangi bir VPS'te veya demo için host PC'de çalışır.

```bash
cd server
pip install -r requirements.txt
uvicorn relay_server:app --host 0.0.0.0 --port 9000
```

- `http://SUNUCU_IP:9000` → durum kontrolü
- `/ingest` → Pi buraya bağlanır
- `/stream` → mobil app buraya bağlanır

## 2. Raspberry Pi HIDS — Push Entegrasyonu

`cloud_push.py`'yi `hids-sensor/sensor/` klasörüne kopyala. Pi'de:

```bash
pip install websocket-client
```

`app.py` içinde şu değişiklikleri yap:

**a) Import ekle (üstte):**
```python
from cloud_push import CloudPusher
```

**b) Pusher oluştur (detector satırının altına):**
```python
# Bulut relay'e push (SUNUCU_IP'yi değiştir)
pusher = CloudPusher("ws://SUNUCU_IP:9000/ingest")
pusher.start()
```

**c) `consumer_loop` içinde, her log yayınında push et:**
Şu satırların yanına (kural tespiti ve xgboost tespiti için):
```python
recent_logs.appendleft(log)
await broadcast({"type": "log", "data": log})
pusher.push(log)   # ← BU SATIRI EKLE
```

Artık Pi her tespiti hem yerel dashboard'a hem buluta gönderir.

## 3. Flutter Mobil App

```bash
flutter create hids_app
cd hids_app
# pubspec.yaml'ı bu repodakiyle değiştir
# lib/main.dart'ı bu repodakiyle değiştir
flutter pub get
```

**main.dart içinde `SERVER_URL`'i ayarla:**
- Android emülatör + host'ta sunucu: `ws://10.0.2.2:9000/stream`
- Gerçek telefon + aynı ağ: `ws://SUNUCU_LOCAL_IP:9000/stream`
- Uzak sunucu: `ws://SUNUCU_PUBLIC_IP:9000/stream`

```bash
flutter run
```

## Demo Senaryosu

1. Bulut relay'i başlat (host PC veya VPS)
2. Pi'de (veya host'ta) HIDS'i push entegrasyonuyla başlat
3. Flutter app'i aç — "Sensör Aktif" görünür
4. Attacker VM'den saldırı yap (nmap, hping3)
5. Mobil app'te canlı tespitler akar, kritik saldırıda bildirim düşer

## Gelecek Çalışma (rapor için)

- FCM (Firebase Cloud Messaging) ile gerçek push bildirim (app kapalıyken)
- TLS/WSS ile şifreli bağlantı
- Sunucuda kalıcı veritabanı (PostgreSQL/TimescaleDB)
- Mobil app'ten SLM chatbot ile doğal dil sorgu
- Çoklu Pi sensör yönetimi (mesh ağı)
