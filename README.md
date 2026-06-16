<h1 align="center">Intrusion Detection System on Raspberry Pi with SHAP and Chatbot Integration for End-Consumers</h1>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white">
  <img alt="XGBoost" src="https://img.shields.io/badge/XGBoost-2.1-FF6600">
  <img alt="scikit-learn" src="https://img.shields.io/badge/scikit--learn-1.6-F7931E?logo=scikitlearn&logoColor=white">
  <img alt="FastAPI" src="https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white">
  <img alt="Raspberry Pi" src="https://img.shields.io/badge/Raspberry%20Pi%204-A22846?logo=raspberrypi&logoColor=white">
  <img alt="SHAP" src="https://img.shields.io/badge/Explainability-SHAP-4B0082">
  <img alt="MITRE" src="https://img.shields.io/badge/MITRE-ATT%26CK-C7233F">
</p>

<p align="center">
  Canlı Dashboard / Live Dashboard: <a href="https://hids-xgboost-shap-slm.onrender.com">hids-xgboost-shap-slm.onrender.com</a><br/>
  <sub>Gerçek sensör bağlı değilken örnek (DEMO) veri gösterir · shows sample (DEMO) data when no sensor is connected</sub>
</p>

<p align="center"><a href="#türkçe">Türkçe</a> | <a href="#english">English</a></p>

![Sistem Mimarisi / System Architecture](image-and-videos/image.jpg)

---

## Türkçe

### Genel Bakış
Bu proje, ev ve IoT ağlarındaki tehditleri uç cihaz (Raspberry Pi 4) üzerinde yerel olarak algılayan, açıklanabilir bir Host-Tabanlı Saldırı Tespit Sistemi (HIDS) prototipidir. Amaç, kurumsal IDS yaklaşımlarını teknik bilgisi olmayan bir ev kullanıcısının ethernet'e takıp anlayabileceği bir cihaza indirmektir.

Tespit, uç cihazda lokal çalışır (XGBoost + kural tabanlı). Her tespitte SHAP ile hangi özniteliğin kararı ne kadar etkilediği hesaplanır. Ağ olaylarını sade dille açıklayan chatbot ise bulut tabanlı Google Gemini API'sine bağlanır; bu sürümde cihaz-içi bir Küçük Dil Modeli (SLM) bulunmaz, gelecek çalışma olarak konumlandırılmıştır (repo adındaki "SLM" başlangıçtaki kapsamdan gelir). Kritik bir saldırıda kullanıcıya Telegram üzerinden anında bildirim gider.

### Problem
Bilgi teknolojilerinin hızlı büyümesiyle karmaşık sistemlerin güvenliği giderek kritikleşmekte, saldırı tespit sistemleri (IDS) modern savunmanın temel bir bileşeni hâline gelmektedir. Ancak güvenlik zincirinin en zayıf halkası insandır: internet kullanıcılarının önemli bir kısmı siber tehditler konusunda yeterli farkındalığa ve kendi cihazlarını koruyacak teknik bilgiye sahip değildir. Bu kullanıcılar teknolojiyle teknik operatör olarak değil son kullanıcı (end-consumer) olarak etkileştiğinden, gelişmiş tehditlere karşı korumasız kalmaktadır. Bu proje, teknik bilgisi olmayan kullanıcıların kolayca benimseyebileceği; Raspberry Pi üzerinde çalışan, SHAP tabanlı açıklanabilir yapay zekâ ve etkileşimli bir chatbot ile desteklenmiş hafif bir IDS çerçevesi sunarak bu boşluğu hedefler.

### Mimari
```
[Saldırgan VM] ─┐  (Pi, ARP-MITM ile araya inline girer)
                ├─► [Raspberry Pi 4: Sniffer → Kural + XGBoost + canlı SHAP]
[Kurban VM]   ─┘                 │  └─ logs/detections.jsonl (kalıcı, MITRE etiketli)
                                 ▼
                       [Bulut Relay (Render, FastAPI/WebSocket)]
                                 │
              ┌──────────────────┼───────────────────────┐
              ▼                  ▼                         ▼
     [Web Dashboard]      [Telegram bildirimi]    [Gemini chatbot]
   canlı akış + KPI +      kritik saldırıda         sade-dil soru/cevap
   olay-detay + SHAP        anlık mobil push
```
Test ortamı: Windows 11 host üzerinde VMware Workstation Pro, iki Ubuntu Server sanal makinesi (saldırgan ve kurban, bridged). Model eğitimi Google Colab (T4 GPU), canlı çıkarım Raspberry Pi 4 (8GB, CPU) üzerinde.

### Özellikler
- CICIoT2023 ile eğitilmiş XGBoost; Pi'de ölçülen çıkarım yaklaşık 2.6–6.1 ms/akış (ortalama ~3.4 ms), model dosyası ~0.4 MB.
- Hibrit tespit: anlık kural katmanı (port tarama, SYN/UDP/ICMP flood, brute-force) ve akış-bazlı XGBoost (3 sn pencere) birlikte çalışır.
- Canlı SHAP: her XGBoost tespitinde kararı en çok etkileyen öznitelikler, XGBoost'un yerel `pred_contribs` (TreeSHAP) özelliğiyle hesaplanır. Ek `shap` kütüphanesi gerektirmediği için Pi üzerinde hafif çalışır; dashboard'da "Neden?" satırı ve detay panelinde bar grafiği olarak görünür.
- MITRE ATT&CK eşlemesi: her tespit ilgili teknikle etiketlenir (T1046, T1498, T1110, T1499, T1190).
- Web dashboard: gerçek zamanlı (WebSocket) akış, KPI'lar, saldırı dağılımı, DEMO/CANLI rozeti, olay-detay paneli (SHAP barları, MITRE, önerilen müdahale) ve Gemini chatbot.
- Mobil bildirim: kritik saldırıda Telegram'a anlık push (tekrar eden saldırılarda bildirim taşkınını önleyen cooldown ile).
- Değerlendirme: `experiments/` altında ground-truth üreteci (`attack-runner.sh`) ve zaman-pencereli eşleştirme defteri (`evaluate_live.ipynb`) ile gerçek recall, false-positive ve Pi gecikmesi ölçülür.

### Sonuçlar
| Metrik | Değer | Kaynak |
|--------|-------|--------|
| Doğruluk (Accuracy) | %99.64 | CICIoT2023 test kümesi |
| F1 | 0.998 | CICIoT2023 test kümesi |
| AUC-ROC | 0.9996 | CICIoT2023 test kümesi |
| Öznitelik sayısı | 40 (canlı hesaplanabilir alt küme) | train/serve parite |
| Pi çıkarım gecikmesi | ~3.4 ms/akış | gerçek donanım ölçümü |

Tablodaki benchmark değerleri veri setinin test kümesine aittir. Canlı testbed başarımı, `experiments/` altında tespitlerin ground-truth ile eşleştirilmesiyle ayrıca ölçülür.

### Nasıl Çalıştırılır?
1. Model eğitimi (Colab): `colab/CICIoT2023_XGBoost_Training.ipynb` → Runtime ▸ Run all. Çıktılar (`xgboost_ciciot2023.joblib`, `scaler.joblib`, `feature_names.json`, `model_meta.json`) `models/` altına gelir.
2. Pi'ye dağıt: `bash hids-sensor/deploy-to-pi.sh <PI_IP> <KULLANICI>`.
3. Sensörü inline başlat: Pi'de `sudo bash /opt/hids-sensor/mitm-run.sh <KURBAN_IP> <SALDIRGAN_IP>`.
4. Dashboard: yukarıdaki Render bağlantısı veya yerel relay.
5. Değerlendirme: saldırgan VM'de `experiments2/attack-runner.sh`, ardından `evaluate_live.ipynb`. Ayrıntılar: [`docs/DEMO-GUIDE.md`](docs/DEMO-GUIDE.md).

### Sınırlar ve Gelecek Çalışma
- Kontrollü bir VM test ortamı kullanılmıştır; büyük ölçekli gerçek trafik değildir.
- Doğal-dil katmanı bulut Gemini'ye bağlıdır; cihaz-içi SLM gelecek çalışmadır.
- Kural katmanı, yüksek hızlı flood'da kurban cevaplarını yanlış etiketleyebilir (backscatter); akış-bazlı XGBoost bu durumda daha sağlamdır.
- Sınıflandırma ikilidir (saldırı/normal); çok-sınıf (saldırı türü) ayrımı gelecek çalışmadır.
- Inline ARP-MITM konumlandırması test ortamı içindir; üretimde pasif TAP/SPAN veya gerçek köprü tercih edilmelidir.

### Repo Yapısı
```
hids-sensor/      Raspberry Pi sensörü (sniffer, flow aggregator, detector, app) + deploy/run scriptleri
sentinel-mesh/    Bulut relay (FastAPI) + web dashboard (static) + Flutter mobil app iskeleti
colab/            CICIoT2023 XGBoost eğitim defteri
models/           Eğitilmiş model, scaler, feature_names, meta
experiments/, experiments2/   Ground-truth üreteci + canlı değerlendirme defteri
docs/             Kurulum, ilerleme, risk ve demo rehberi
project/          Fonksiyonel gereksinimler + araç/sürüm dökümü (toolkit.json)
```

---

## English

### Overview
This project is an explainable, edge-deployed Host-based Intrusion Detection System (HIDS) that detects threats in home and IoT networks locally on a Raspberry Pi 4. The goal is to bring enterprise IDS ideas down to a device a non-technical end-user can plug into their ethernet and understand.

Detection runs locally on the edge device (XGBoost + rule-based). For every detection, SHAP computes which feature drove the decision and by how much. The plain-language chatbot that explains network events connects to the cloud Google Gemini API; this version has no on-device Small Language Model (SLM), which is positioned as future work (the "SLM" in the repo name reflects the original scope). On a critical attack, the user receives an instant Telegram alert.

### Problem
As information technologies grow, securing complex systems becomes increasingly critical, and intrusion detection systems (IDS) are a core mechanism of modern defense. The weakest link, however, is the human: many internet users lack both the awareness of cyber threats and the technical knowledge to protect their own devices. Because they interact with technology as end-consumers rather than operators, they remain continuously exposed to sophisticated threats. This project targets that gap with a lightweight, Raspberry Pi-based IDS that adds SHAP-based explainable AI and an interactive chatbot so non-technical users can understand and act on what happens on their network.

### Architecture
```
[Attacker VM] ─┐  (Pi sits inline via ARP-MITM)
               ├─► [Raspberry Pi 4: Sniffer → Rules + XGBoost + live SHAP]
[Victim VM]  ─┘                  │  └─ logs/detections.jsonl (persistent, MITRE-tagged)
                                 ▼
                       [Cloud Relay (Render, FastAPI/WebSocket)]
                                 │
              ┌──────────────────┼───────────────────────┐
              ▼                  ▼                         ▼
       [Web Dashboard]     [Telegram alert]         [Gemini chatbot]
   live feed + KPIs +     instant mobile push       plain-language Q&A
   event detail + SHAP     on critical attacks
```
Test environment: VMware Workstation Pro on a Windows 11 host, two Ubuntu Server VMs (attacker and victim, bridged). The model is trained on Google Colab (T4 GPU); live inference runs on a Raspberry Pi 4 (8GB, CPU).

### Features
- XGBoost trained on CICIoT2023; measured inference on the Pi is about 2.6–6.1 ms/flow (avg ~3.4 ms), with a ~0.4 MB model file.
- Hybrid detection: an instant rule layer (port scan, SYN/UDP/ICMP flood, brute-force) plus a flow-based XGBoost layer (3 s window).
- Live SHAP: for each XGBoost detection, top contributing features are computed via XGBoost's native `pred_contribs` (TreeSHAP). It needs no heavy `shap` dependency, so it stays light on the Pi; results show as a "Why?" line and a bar chart in the event-detail panel.
- MITRE ATT&CK mapping: each detection is tagged with its technique (T1046, T1498, T1110, T1499, T1190).
- Web dashboard: real-time (WebSocket) feed, KPIs, attack distribution, DEMO/LIVE badge, event-detail panel (SHAP bars, MITRE, recommended actions), and a Gemini chatbot.
- Mobile alerts: instant Telegram push on critical attacks (with a cooldown that prevents alert floods on repeated attacks).
- Evaluation: a ground-truth generator (`attack-runner.sh`) and a time-window matching notebook (`evaluate_live.ipynb`) under `experiments/` measure real recall, false-positive rate, and Pi latency.

### Results
| Metric | Value | Source |
|--------|-------|--------|
| Accuracy | 99.64% | CICIoT2023 test set |
| F1 | 0.998 | CICIoT2023 test set |
| AUC-ROC | 0.9996 | CICIoT2023 test set |
| Feature count | 40 (live-computable subset) | train/serve parity |
| Pi inference latency | ~3.4 ms/flow | real hardware measurement |

Benchmark values are on the dataset's test set. Live-testbed performance is measured separately under `experiments/` by matching detections against ground truth.

### How to Run
1. Train (Colab): `colab/CICIoT2023_XGBoost_Training.ipynb` → Runtime ▸ Run all. Artifacts (`xgboost_ciciot2023.joblib`, `scaler.joblib`, `feature_names.json`, `model_meta.json`) land in `models/`.
2. Deploy to the Pi: `bash hids-sensor/deploy-to-pi.sh <PI_IP> <USER>`.
3. Start the sensor inline: on the Pi, `sudo bash /opt/hids-sensor/mitm-run.sh <VICTIM_IP> <ATTACKER_IP>`.
4. Dashboard: the Render link above or a local relay.
5. Evaluate: on the attacker VM run `experiments2/attack-runner.sh`, then `evaluate_live.ipynb`. Details: [`docs/DEMO-GUIDE.md`](docs/DEMO-GUIDE.md).

### Limitations and Future Work
- A controlled VM test environment is used, not large-scale real traffic.
- The natural-language layer depends on cloud Gemini; an on-device SLM is future work.
- Under high-rate floods, the rule layer can mislabel victim responses (backscatter); the flow-based XGBoost layer is more robust in that case.
- Classification is binary (attack/normal); multi-class (attack family) is future work.
- The inline ARP-MITM placement is for the testbed; production should use a passive TAP/SPAN or a true bridge.

### Repository Structure
```
hids-sensor/      Raspberry Pi sensor (sniffer, flow aggregator, detector, app) + deploy/run scripts
sentinel-mesh/    Cloud relay (FastAPI) + web dashboard (static) + Flutter mobile app skeleton
colab/            CICIoT2023 XGBoost training notebook
models/           Trained model, scaler, feature_names, meta
experiments/, experiments2/   Ground-truth generator + live evaluation notebook
docs/             Setup, progress, risk, and demo guide
project/          Functional requirements + tool/version inventory (toolkit.json)
```

---

Lisans / License: [`LICENSE`](LICENSE)
