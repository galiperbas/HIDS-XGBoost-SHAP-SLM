# İlerleme Günlüğü — 04: XGBoost Model Eğitimi (CICIoT2023)

**Tarih:** 2026-06-11
**İlgili Gereksinim:** FR-04 — Tespit Modeli Eğitimi
**Durum:** Eğitim notebook'u hazır (Colab'da çalıştırılacak)

## Yapılanlar

### Veri Seti Seçimi: CICIoT2023

Önceki benchmark çalışmasında NSL-KDD, UNSW-NB15 ve CICIDS-2017 kullanılmıştı.
Canlı sistem için **CICIoT2023** (Canadian Institute for Cybersecurity, 2023)
veri setine geçildi. Gerekçeler:

- **Güncel:** 2023 verisi; NSL-KDD (1999) ve CICIDS-2017'den çok daha modern
- **Proje uyumu:** Gerçek akıllı ev ortamında 105 IoT cihazı (kamera, hoparlör,
  sensör, akıllı priz) ile üretildi — projenin akıllı ev / IoT konusuyla birebir
- **Modern saldırılar:** 33 saldırı türü, 7 kategori (DDoS, DoS, Recon,
  Web-based, Brute Force, Spoofing, Mirai botnet)
- **Kanıtlanmış:** Literatürde XGBoost ile %99+ başarı [Neto et al., 2023]

### Eğitim Notebook'u

`colab/CICIoT2023_XGBoost_Training.ipynb` oluşturuldu. İçerik:

1. CICIoT2023 indirme (kagglehub)
2. Bellek dostu örnekleme (büyük veri seti için alt küme)
3. Binary etiketleme (Normal=0, Saldırı=1)
4. RobustScaler + SMOTE ön işleme
5. **Raspberry Pi hedefli** XGBoost eğitimi (n_estimators=150, max_depth=8)
6. Değerlendirme (Accuracy, F1, AUC-ROC, FPR)
7. SHAP açıklanabilirlik analizi (beeswarm + bar)
8. Model kaydetme + çıkarım hız testi

### Çıktılar (Colab'dan indirilecek)

| Dosya | Açıklama |
|-------|----------|
| `xgboost_ciciot2023.joblib` | Eğitimli model (sıkıştırılmış) |
| `scaler.joblib` | Öznitelik normalizasyonu |
| `feature_names.json` | Öznitelik sırası (canlı tespitte kritik) |
| `model_meta.json` | Model metaverisi ve metrikler |

## Teknik Kararlar

### Raspberry Pi Optimizasyonu — Quantization Gerekli Değil

XGBoost ağaç-tabanlı bir modeldir; quantization (derin öğrenme için gereken
bir teknik) burada gerekmez. Model boyutu sıkıştırma ile ~1-5MB, çıkarım süresi
Pi 4 CPU'da <5ms beklenir. Hafiflik için ağaç sayısı (150) ve derinlik (8)
sınırlı tutuldu.

### SHAP — Pi'de Çalışabilir

TreeSHAP, XGBoost ile çok hızlıdır ve Pi 4'te canlı açıklanabilirlik için
uygundur. Her anomali tespitinde "neden?" sorusuna cevap verecek.

### SLM — İleri Aşamaya Bırakıldı

8GB Pi'de küçük dil modeli (TinyLlama 1.1B, Phi-3-mini quantized) çalışabilir
ancak gerçek zamanlı değil (~saniyeler/yanıt). İlk etapta XGBoost + SHAP'a
odaklanılıp, SLM tabanlı log analizi gelecek çalışma olarak konumlandırıldı.

## Açık Konu: Paket-bazlı vs Akış-bazlı Öznitelikler

CICIoT2023 **akış-bazlı** (flow-based) öznitelikler kullanır. Canlı
sniffer'ımız şu an **paket-bazlı** çalışıyor. Bir sonraki adımda iki seçenekten
biri seçilecek:

- **(A)** Sniffer'a akış toplama (flow aggregation) ekle — daha doğru, model
  uyumlu
- **(B)** Paket-bazlı basit özniteliklerle ayrı model eğit — daha hızlı ama
  daha az doğru

## Sonraki Adımlar

1. Notebook'u Colab'da çalıştır, 4 model dosyasını indir
2. Dosyaları `models/` klasörüne koy
3. `detector.py`'yi gerçek XGBoost ile entegre et
4. Akış-bazlı öznitelik kararını ver (A veya B)
5. Canlı trafikte test (Attacker → Normal saldırıları)
