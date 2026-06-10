# HIDS Sensor — Canlı Ağ Tespit Motoru

Host PC veya Raspberry Pi üzerinde çalışan, Scapy ile canlı trafik yakalayıp
saldırıları tespit eden ve WebSocket ile dashboard'a yayınlayan sensör.

## Mimari

```
[SimVM-Attacker] ──┐
                   ├──> [Host PC / Raspberry Pi]
[SimVM-Normal] ────┘     sniffer.py → detector.py → app.py (WebSocket)
                                                         │
                                                    [Dashboard]
```

## Bileşenler

| Dosya | Görev |
|-------|-------|
| `sniffer.py` | Scapy ile paket yakalama + akış özniteliği çıkarımı |
| `detector.py` | Kural tabanlı + XGBoost tespit |
| `app.py` | FastAPI + WebSocket yayını |

## Kurulum (Windows host)

Önce Npcap kurulu olmalı (Wireshark ile gelir).

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Çalıştırma

1. Ağ arayüzünü bul:
```powershell
python sensor/sniffer.py
```

2. Sensörü başlat (Yönetici PowerShell):
```powershell
python sensor/app.py --iface "Ethernet"
```

3. `http://localhost:8000` → durum kontrolü
4. Dashboard'u bağla (cybercore-command frontend, ws://localhost:8000/ws)

## XGBoost Modeli Entegrasyonu

Benchmark'tan eğitilmiş modeli kaydet:
```python
import joblib
joblib.dump(model, "model.joblib")
```

`app.py` içinde:
```python
detector = AnomalyDetector(model_path="model.joblib")
```

## Tespit Yöntemleri

| Saldırı | Yöntem | Tetikleyici |
|---------|--------|-------------|
| Port Scan | Kural | 1 sn'de >=15 farklı port |
| SYN Flood | Kural | 1 sn'de >=30 SYN |
| DoS Flood | Kural | 1 sn'de >=100 paket |
| Brute Force | Kural | 22/21 portuna >=20 paket |
| Genel | XGBoost | Öğrenilmiş model (eklenince) |
