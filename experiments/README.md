# Canlı Sistem Değerlendirmesi (Tez "Results" çekirdeği)

Bu klasör, sistemin **gerçek testbed başarımını** ölçer — CICIoT2023 test metriği
(model doğruluğu) ile karıştırılmamalıdır. Üç parça:

| Dosya | Nerede çalışır | Görev |
|-------|----------------|-------|
| `attack-runner.sh` | Saldırgan VM | Kontrollü saldırı + iyi huylu trafik üretir, her pencerenin zamanını + MITRE ID'sini `ground_truth.csv`'ye yazar |
| (sensör) `logs/detections.jsonl` | Pi / host sensör | Her tespiti tam ISO zaman damgasıyla diske yazar (sensör otomatik üretir) |
| `evaluate_live.ipynb` | Host / Colab | İki dosyayı eşleştirir → recall, false positive, Pi gecikmesi + grafikler |

## Adımlar

1. **Model güncel mi?** Colab'da yeniden eğitilen 4 dosya `models/` altında ve Pi'ye
   gönderilmiş olmalı (`bash hids-sensor/deploy-to-pi.sh <PI_IP>`).
2. **Sensörü CANLI başlat** (DEMO kapalı). Pi inline: `sudo bash hids-sensor/mitm-run.sh <KURBAN_IP> <SALDIRGAN_IP>`.
   Sensör çalışırken `logs/detections.jsonl` dolar.
3. **Saldırı senaryosunu koştur** (saldırgan VM):
   ```bash
   sudo bash attack-runner.sh <KURBAN_IP> 20
   ```
4. **Dosyaları topla:** Pi'den `detections.jsonl` + saldırgandan `ground_truth.csv`'yi
   bu klasöre kopyala.
5. **Değerlendir:** `evaluate_live.ipynb`'i çalıştır → metrikler ve `eval_*.png` grafikleri.

## Notlar
- Saatler aynı saat diliminde ve NTP ile senkron olmalı (eşleştirme zaman penceresine dayanır).
- `Slowloris` gibi yavaş saldırılar kural katmanınca kaçırılabilir — bu beklenen bir
  sınırdır, Discussion'da dürüstçe raporlanır.
- Saldırı araçları (nmap/hping3/hydra/slowhttptest) yalnızca kendi izole laboratuvarında kullanılır.
