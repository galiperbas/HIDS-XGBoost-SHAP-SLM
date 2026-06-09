# Risk Kaydı (Risk Log)

Bu dosya, proje boyunca tespit edilen riskleri ve bunlara karşı planlanan
önlemleri kaydeder. Erken tespit edilen riskler burada tutulur.

---

## R-01 — Demo Günü Ağ Bağımlılığı Riski

**Tespit Tarihi:** 2026-06-09
**Önem:** Yüksek
**İlgili Modül:** Ağ Köprüleme ve Trafik Yönlendirme (FR-02)

### Açıklama

VM, Bridged ağ modunda çalışmaktadır ve IP adresini bağlı olduğu fiziksel
ağdan (DHCP) alır. Geliştirme şu an mobil hotspot üzerinden yapılıyor; ancak
demo, üniversite ağı (eduroam) üzerinden yapılacaktır.

Bu durum iki risk doğurur:

1. **IP aralığı değişimi:** eduroam, mevcut `172.19.x.x` aralığından farklı
   bir IP bloğu atayacaktır. Sabit IP varsayımına dayanan yapılandırmalar
   kırılabilir.

2. **İstemci izolasyonu (client isolation):** Kurumsal/kampüs Wi-Fi ağları
   genellikle aynı ağdaki cihazların birbirini görmesini engeller. Bu,
   VM → host → Raspberry Pi trafik zincirini (FR-02) tamamen bozabilir.

### Önlem / Planlanan Çözüm

Demo için trafik zinciri **kampüs ağından bağımsız** olmalıdır:

- Host bilgisayar ile Raspberry Pi, **doğrudan Ethernet kablosu (RJ45)** ile
  bağlanarak izole bir ağ oluşturur. Bu segment eduroam'dan etkilenmez.
- İnternet erişimi gerekiyorsa, VM'e ayrı bir adaptör üzerinden (NAT)
  sağlanır (dual-adapter yaklaşımı).
- Trafik yakalama zinciri yalnızca fiziksel kablo bağlantısına dayanır.

> Bu çözüm FR-02 aşamasında detaylandırılıp uygulanacaktır.

### Durum

Açık (FR-02 aşamasında ele alınacak)

---

## R-02 — Donanım Kaynağı Kısıtı (Raspberry Pi 4)

**Tespit Tarihi:** 2026-06-09
**Önem:** Orta
**İlgili Modül:** Veri İşleme (FR-03), Tespit (FR-04)

### Açıklama

Raspberry Pi 4 (8GB RAM, ARM mimarisi) sınırlı kaynağa sahiptir. Gerçek
zamanlı paket işleme, öznitelik çıkarımı ve ML çıkarımının (inference) bu
donanımda düşük gecikmeyle çalışması gerekir.

### Önlem / Planlanan Çözüm

- Hafif (lightweight) öznitelik çıkarım araçları tercih edilecek.
- ML modeli ARM uyumlu ve sıkıştırılmış olacak (referans proje: <5 MB,
  ~10 ms çıkarım).

### Durum

İzleniyor
