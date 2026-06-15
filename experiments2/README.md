# Experiment 2 — Kontrollü / İyileştirilmiş Canlı Değerlendirme

Experiment 1 (baseline) bulgularına göre iyileştirilmiş ikinci tur. Tezde
"baseline → iyileştirilmiş senaryo" olarak sunulabilir.

## Experiment 1'e göre düzeltmeler
| # | Sorun (exp1) | exp2 çözümü |
|---|--------------|-------------|
| 1 | XGBoost neredeyse görünmez | Kontrollü hız → paket kuyruğu taşmaz, akışlar düzgün oluşur |
| 2 | Flood backscatter "PortScan" sanılıyor | hping3 sabit kaynak port (`-k -s`) → yanlış etiket yok |
| 3 | `--flood` host/dashboard'ı dondurdu | Sınırlı hız (~400 pps) + dashboard render throttle |
| 4 | Saat kayması | Aşağıdaki senkron adımı + notebook'ta otomatik ofset (yedek) |
| 5 | PortScan penceresi 0 sn | nmap tüm portları sınırlı hızda tarar → gerçek pencere |
| 6 | Slowloris atlandı | Saf Python slowloris (slowhttptest gerekmez) |
| 7 | Log kirlenmesi | Çalıştırma öncesi Pi logu sıfırlanır |
| 8 | Benign zayıf | Daha zengin benign (HTTP+DNS+ping) |

## Çalıştırma (sırayla)

### 0. Hazırlık (önemli — temiz veri için)
**Pi'de — logu sıfırla** (eski veriyle karışmasın):
```bash
> /opt/hids-sensor/logs/detections.jsonl
```
**Saatleri senkronla** (Pi + saldırgan + kurban) — eşleştirme için:
```bash
sudo timedatectl set-ntp true && timedatectl status   # "synchronized: yes" görmelisin
```
NTP eduroam'da çalışmazsa: bir makineyi referans al, diğerlerinde
`sudo date -s "YYYY-MM-DD HH:MM:SS"` ile elle eşitle. (Olmazsa notebook otomatik ofsetle düzeltir.)

### 1. Sensörü CANLI başlat (Pi)
```bash
sudo bash /opt/hids-sensor/mitm-run.sh <KURBAN_IP> <SALDIRGAN_IP>
```
`[DETECTOR] XGBoost modeli yüklendi (40 öznitelik)` görmelisin.

### 2. Saldırı senaryosu (saldırgan VM)
`attack-runner.sh`'i bu klasörden saldırgana kopyala, sonra:
```bash
sudo bash attack-runner.sh <KURBAN_IP> 25
```
(~4-5 dk; kontrollü hız, host donmaz.)

### 3. Değerlendir (host)
```bash
scp raspberry@<PI_IP>:/opt/hids-sensor/logs/detections.jsonl .
scp <kullanıcı>@<SALDIRGAN_IP>:~/ground_truth.csv .
```
`evaluate_live.ipynb` → Run All. Çıktı: recall, FP, Pi gecikmesi, `eval_*.png`.

## Beklenen iyileşme (exp1 → exp2)
- Daha çok ve daha temiz XGBoost tespiti (sparse değil)
- Doğru saldırı etiketleri (PortScan yalnızca gerçek taramada)
- Donma yok
- Slowloris satırı: kural KAÇIRIR (FN) — XGBoost yakalarsa hibrit değerin kanıtı
