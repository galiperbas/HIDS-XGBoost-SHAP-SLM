# 🎬 Demo Çalıştırma Rehberi (Sunum / Savunma)

Bu dosya, sistemi sıfırdan canlı çalıştırmak için izlenecek komutları içerir.
Pencereler: **Host (Windows)**, **Pi (SSH)**, **Saldırgan VM**.

## Mimari (tek bakış)
```
[Saldırgan VM] ──┐ (ARP-MITM ile Pi araya girer)
                 ├──► [Raspberry Pi: sniffer→XGBoost+kural+SHAP] ──push──► [Render Relay] ──► [Web Dashboard + Chatbot]
[Kurban VM]    ──┘                                    └─ logs/detections.jsonl (kalıcı)
```
- **Dashboard:** https://hids-xgboost-shap-slm.onrender.com
- Tespit lokal (Pi), doğal dil açıklama bulut (Gemini chatbot). Cihaz-içi SLM yok.

## Güncel IP'ler (her açılışta değişebilir!)
DHCP rastgele dağıtır. Başlamadan önce öğren:
- **Pi:** `ip a` → `eth0` satırındaki `192.168.137.x`
- **Kurban / Saldırgan VM:** her birinde `ip a`

> Örnek (bu kuruluşta): Pi `.35`, Kurban `.201`, Saldırgan `.85`. Aşağıdaki komutlarda
> kendi güncel IP'lerinle değiştir.

---

## A) Tek seferlik kurulum (zaten yapıldıysa atla)

**Host (Git Bash, proje klasöründe)** — kod + modeli Pi'ye gönder:
```bash
bash hids-sensor/deploy-to-pi.sh <PI_IP> raspberry
```
**Pi (SSH)** — gerekli kütüphaneler (özellikle scikit-learn ŞART):
```bash
/opt/hids-sensor/sensor/venv/bin/pip install scikit-learn
```
Doğrula: `cat /opt/hids-sensor/models/model_meta.json` → `"n_features": 40` olmalı.

---

## B) Canlı demo (sunum sırası)

### 1. Pi'de sensörü başlat — Pi (SSH)
```bash
sudo bash /opt/hids-sensor/mitm-run.sh <KURBAN_IP> <SALDIRGAN_IP>
```
Beklenen: `[DETECTOR] XGBoost modeli yüklendi (40 öznitelik)` + `[CLOUD] Bağlandı: wss://...`.
Pencereyi açık bırak. (Ctrl+C → ARP temizlenir.)

### 2. Dashboard'u aç — Host (tarayıcı)
https://hids-xgboost-shap-slm.onrender.com
- Sağ üstte **CANLI** + **1 Sensör** görünmeli (DEMO değil). DEMO görünürse: **Ctrl+Shift+R** (sayfayı sert yenile).

### 3. Saldırıları başlat — Saldırgan VM
`attack-runner.sh` saldırgan VM'de olmalı (yoksa host'tan kopyala:
`scp experiments/attack-runner.sh <kullanıcı>@<SALDIRGAN_IP>:~/`).
```bash
sudo bash attack-runner.sh <KURBAN_IP> 20
```
Dashboard'da canlı tespitler akar; kritik saldırıda kırmızı uyarı düşer; her tespitin
altında **"Neden: …"** (SHAP/kural gerekçesi) görünür.

### 4. Chatbot'u göster — Dashboard (sağ alttaki 🛡️)
Sor: *"Ağımda tehlike var mı?"*, *"Şu an ne oluyor?"* → sade Türkçe açıklama.

### 5. (Opsiyonel) Bilimsel değerlendirme — Host
Pi'den ve saldırgandan dosyaları al, `experiments/evaluate_live.ipynb`'i çalıştır:
```bash
scp raspberry@<PI_IP>:/opt/hids-sensor/logs/detections.jsonl experiments/
scp <kullanıcı>@<SALDIRGAN_IP>:~/ground_truth.csv experiments/
```
→ recall, false positive, Pi gecikmesi + grafikler.

---

## C) Sorun giderme
| Belirti | Sebep / Çözüm |
|--------|----------------|
| `No module named 'sklearn'` | Pi venv'inde scikit-learn yok → `/opt/hids-sensor/sensor/venv/bin/pip install scikit-learn` |
| `40 öznitelik bekliyor ama model 46` | Eski model → Colab defterini güncel haliyle çalıştır, `deploy-to-pi.sh` ile tekrar gönder |
| Dashboard **DEMO** diyor ama sensör bağlı | Tarayıcı eski JS'i cache'lemiş → **Ctrl+Shift+R**. Hâlâ ise `/api/summary`'de `demo_mode` var mı bak (yoksa Render eski kodu çalıştırıyordur → yeni kodu push/deploy et) |
| Pi araya giremiyor / trafik görünmüyor | ARP-MITM çalışıyor mu? `mitm-run.sh` IP'leri doğru mu? VMware **bridged** mod mu? |
| `apt`/`pip` "Temporary failure resolving" | eduroam DNS filtresi → VM/Pi'de `nameserver 192.168.137.1` kullan ya da kurulumu mobil hotspot'ta yap |
| IP'ler değişti | Tüm komutlar IP'yi argüman alır; `ip a` ile güncelini bul, komutlarda değiştir |
