# Ortam Kurulumu — FR-01.1 (Sanal Makine Provisioning)

**Tarih:** 2026-06-09
**İlgili Gereksinim:** FR-01.1 — Normal Arka Plan Trafik Simülasyonu
**Aktör:** Sanal Makine (VM)
**Durum:** Ortam hazır (VM ayağa kaldırıldı, ağ doğrulandı)

## Amaç

FR-01.1'in çalışacağı sanal makine ortamının kurulması. Bu VM, akıllı ev /
iç ağ ortamına ait normal arka plan trafiğini (HTTP, HTTPS, DNS, MQTT)
simüle eden aktör olarak görev yapacaktır.

## Kullanılan Araçlar (toolkit.json ile uyumlu)

| Araç | Sürüm |
|------|-------|
| Hipervizör | VMware Workstation Pro 26H1 |
| Misafir İşletim Sistemi | Ubuntu Server 26.04 LTS |

## VM Donanım Yapılandırması

| Parametre | Değer |
|-----------|-------|
| VM Adı | SimVM-Normal |
| Bellek (RAM) | 2 GB (2048 MB) |
| İşlemci | 2 çekirdek |
| Disk | 20 GB (LVM, ext4) |
| Ağ Adaptörü | Bridged (Replicate physical network connection state: açık) |
| SSH | OpenSSH server kurulu, parola kimlik doğrulaması açık |
| Konum | C:\Users\galip\VMs (OneDrive senkronizasyonu dışında) |

## Ağ Doğrulaması

Kurulum sonrası ağ bağlantısı doğrulandı:

- **Arayüz:** ens33 (state: UP)
- **Atanan IP:** 172.19.237.37/20 (DHCP, dynamic)
- **Bağlantı testi:** `ping -c 3 8.8.8.8` → 3/3 paket alındı, %0 kayıp

> Not: Bridged mod, VM'e fiziksel ağdan doğrudan bir IP atar. Mevcut test
> ortamı mobil hotspot olduğu için IP `172.19.x.x` bloğundan (özel/private
> IP, RFC 1918) gelmiştir. Bridged modun doğru çalıştığını teyit eder.

## Mimari Konum

Bu VM, projenin trafik üretim zincirinin başlangıç noktasıdır:

```
[SimVM-Normal] --> vNIC --> Host (fiziksel arayüz) --> RJ45 --> Raspberry Pi 4
   (FR-01.x)                    (FR-02.1)                        (FR-02.2)
```

## Sonraki Adım

- HTTP / HTTPS / DNS / MQTT normal trafik üreticilerinin VM üzerine kurulması
  ve sürekli, gerçekçi trafik paternlerinin üretilmesi (FR-01.1 ana görevi).
