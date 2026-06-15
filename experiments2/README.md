# Experiment 2 — Kontrollü / İyileştirilmiş Canlı Değerlendirme

Experiment 1 (baseline) bulgularına göre iyileştirilmiş ikinci tur. Tezde
"baseline → iyileştirilmiş senaryo" olarak sunulabilir.

---

## ⚡ TEMİZ TEK KOŞU — kopyala-yapıştır (döndüğünde direkt uygula)

> IP'ler: Pi `192.168.137.35` (raspberry), kurban `192.168.137.201`, saldırgan
> `192.168.137.85` (galip). **Pi'yi açtıysan IP değişmiş olabilir — her makinede `ip a` ile teyit et.**
> Pencereler: **A = Host (VS Code terminal)** · **B = Pi (SSH)** · **C = Saldırgan VM**

```bash
# A: güncel scripti saldırgana gönder + eski sonuç dosyalarını sil
scp experiments2/attack-runner.sh galip@192.168.137.85:~/
rm -f experiments2/ground_truth.csv experiments2/detections.jsonl

# B (Pi): logu temizle + saati senkronla + sensörü başlat
> /opt/hids-sensor/logs/detections.jsonl
sudo timedatectl set-ntp true
sudo bash /opt/hids-sensor/mitm-run.sh 192.168.137.201 192.168.137.85
#   -> "[DETECTOR] XGBoost modeli yüklendi (40 öznitelik)" görmelisin. Pencereyi açık bırak.

# C (saldırgan): tek koşu (~5 dk, kontrollü hız)
sudo bash attack-runner.sh 192.168.137.201 25

# A: sonuçları topla
scp raspberry@192.168.137.35:/opt/hids-sensor/logs/detections.jsonl experiments2/
scp galip@192.168.137.85:~/ground_truth.csv experiments2/

# A: hızlı doğrulama (Slowloris kaynağı + XGBoost payı)
grep -o '"attack_type":"[^"]*"' experiments2/detections.jsonl | sort | uniq -c
grep -o '"method":"[^"]*"' experiments2/detections.jsonl | sort | uniq -c
```
Son adım: `experiments2/evaluate_live.ipynb` → **(base) kernel → Run All**.

### 📤 Claude'a şunları yapıştır
1. İki `grep` çıktısı (attack_type + method dağılımı)
2. Notebook: **"Otomatik saat ofseti…"** satırı + **`res` (pencere tablosu)** + **"Özet metrikler"** + **"Pi çıkarım gecikmesi"**
3. Telegram bildirimi düştü mü? · tespite tıklayınca panel+SHAP açıldı mı?

→ Bunlarla tezin **Results/Discussion** tablosunu yazarız.

---

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
