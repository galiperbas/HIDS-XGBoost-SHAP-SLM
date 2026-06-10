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

---

## R-03 — Eduroam DNS Filtrelemesi ve Statik IP Çakışması

**Tespit Tarihi:** 2026-06-10
**Önem:** Orta
**İlgili Modül:** Ortam Kurulumu (FR-01), Dağıtım

### Açıklama

Saldırgan makinede statik IP'ye (172.19.237.200/20) geçildiğinde, eduroam
ağının harici DNS sorgularını filtrelemesi nedeniyle ad çözümlemesi başarısız
oldu (`Temporary failure resolving`). Bu durum, `apt update` ve paket kurulum
adımlarını engelledi. Statik yapılandırmada 8.8.8.8 gibi harici DNS
sunucularına erişim kampüs ağı tarafından kısıtlanmaktadır.

### Önlem / Uygulanan Çözüm

- Paket kurulumları geçici olarak DHCP moduna dönülerek (kampüsün yerel DNS'i
  ile) tamamlandı.
- Kalıcı statik yapılandırmada DNS sunucusu olarak harici adres yerine
  **gateway IP'si (172.19.224.1)** tanımlandı; böylece ad çözümlemesi kampüs
  içi DNS üzerinden çalışır hale getirildi.

### Mimari Ders

Kurumsal/kısıtlı ağlarda dağıtım yapan sistemler, harici DNS erişimine
güvenmemelidir. Üretim/demo yapılandırması yerel DNS veya gateway tabanlı
çözümlemeye dayanmalı; bağımlılık kurulumu (build-time) ile çalışma-zamanı
(runtime) ağ varsayımları ayrıştırılmalıdır. Bu, projenin "kurumsal IT
kısıtlamaları altında çalışabilirlik" hedefiyle doğrudan örtüşür.

### Durum

Çözüldü (yapılandırma kalıcılaştırıldı)

---

## R-04 — Python Bağımlılık Yönetimi (PEP 668)

**Tespit Tarihi:** 2026-06-10
**Önem:** Düşük
**İlgili Modül:** Ortam Kurulumu (FR-01), İleride SLM Betikleri (FR-05+)

### Açıklama

Ubuntu 26.04, PEP 668 gereği sistem Python'una doğrudan `pip` kurulumunu
engellemektedir (`externally-managed-environment`). Saldırgan makinede
`slowloris` kurulumu bu engele takıldı ve `--break-system-packages` bayrağıyla
aşıldı.

### Risk Değerlendirmesi

- **Saldırgan makine (kabul edilebilir):** Tek kullanımlık, izole bir test
  ortamı olduğundan sistem Python'unun kirletilmesi kabul edilebilir bir
  risktir.
- **HIDS / SLM tarafı (kabul edilemez):** Tespit motoru ve gelecekteki SLM
  betikleri için `--break-system-packages` KULLANILMAMALIDIR. Bağımlılık
  kararsızlığını (dependency hell) önlemek için bu bileşenler izole bir
  **sanal ortam (venv)** içinde çalıştırılmalıdır.

### Önlem / Planlanan Çözüm

- HIDS backend'i ve SLM bileşenleri `python3 -m venv` ile izole edilecek.
- Bağımlılıklar `requirements.txt` ile sürüm sabitlenerek yönetilecek.
- Üretim dağıtımı için (Raspberry Pi) Docker konteynerleştirme değerlendirilecek.

### Durum

İzleniyor (HIDS tarafında venv zorunlu kılındı)
