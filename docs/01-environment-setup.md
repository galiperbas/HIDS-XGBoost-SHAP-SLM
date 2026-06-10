# Ortam Kurulumu — FR-01 (Sanal Laboratuvar Provisioning)

**Tarih:** 2026-06-10
**İlgili Gereksinim:** FR-01 — Sanal test ortamının hazırlanması
**Durum:** Tamamlandı (iki VM ayağa kaldırıldı, statik IP'ler atandı, araçlar kuruldu)

## Amaç

Saldırı simülasyonu ve normal trafik üretimi için izole bir sanal laboratuvar
ortamının kurulması. Ortam iki sunucudan oluşur: normal trafik/servis üreten
kurban makine (SimVM-Normal) ve saldırı araçlarını barındıran saldırgan makine
(SimVM-Attacker).

## Kullanılan Araçlar (toolkit.json ile uyumlu)

| Araç | Sürüm |
|------|-------|
| Hipervizör | VMware Workstation Pro 26H1 |
| Misafir İşletim Sistemi | Ubuntu Server 26.04 LTS |

## VM Yapılandırması

| Parametre | SimVM-Normal | SimVM-Attacker |
|-----------|-------------|----------------|
| Rol | Kurban / hedef | Saldırgan |
| Bellek (RAM) | 2 GB | 2 GB |
| İşlemci | 2 çekirdek | 2 çekirdek |
| Disk | 20 GB | 20 GB (full clone) |
| Statik IP | 172.19.237.100/20 | 172.19.237.200/20 |
| Ağ Adaptörü | Bridged | Bridged |
| Klonlama | Orijinal | Full clone (Normal'den) |

## SimVM-Normal — Kurulan Servisler

Kurban makine, saldırıların hedefleyeceği servisleri barındırır:

| Servis | Port | Dönem | Saldırı senaryosu |
|--------|------|-------|-------------------|
| Apache HTTP | 80 | Klasik | DDoS, web tarama (nikto) |
| OpenSSH | 22 | Klasik | Brute force (hydra) |
| vsftpd FTP | 21 | Klasik | Brute force, anonim erişim |
| SmartHome AI Assistant API (FastAPI) | 8080 | Modern | API abuse, prompt injection, veri sızdırma |

> SmartHome AI Assistant API, projenin güncel saldırı yüzeyini temsil eder.
> Klasik servislerin yanında modern bir AI servisi bulundurmak, çok katmanlı
> tespit mimarisinin (bkz. architecture) test edilmesini mümkün kılar.

## SimVM-Attacker — Kurulan Araçlar

| Araç | Amaç |
|------|------|
| nmap | Port tarama, servis keşfi |
| hping3 | Paket üretimi, SYN flood / DDoS |
| hydra | SSH/FTP brute force |
| nikto | Web sunucu zafiyet taraması |
| slowloris | Yavaş HTTP DoS saldırısı |
| build-essential, gcc, g++ | Derleme bağımlılıkları |

## Statik IP Yapılandırması (Netplan)

Klon makinede ağ arayüzü eşleşmesi MAC adresi üzerinden sabitlenmiştir
(klonlamada arayüz isimlendirme tutarsızlığını önlemek için):

```yaml
network:
  version: 2
  ethernets:
    ens33:
      match:
        macaddress: 00:0c:29:45:e1:43
      set-name: ens33
      dhcp4: no
      addresses:
        - 172.19.237.200/20
      routes:
        - to: default
          via: 172.19.224.1
      nameservers:
        addresses: [172.19.224.1, 8.8.8.8]
```

## Karşılaşılan Sorunlar ve Çözümler

| Sorun | Çözüm |
|-------|-------|
| Klonda `ens33` bulunamadı (`Cannot find unique matching interface`) | İkinci netplan dosyası (`00-installer-config.yaml`) silindi, MAC tabanlı `match` eklendi |
| Eduroam DNS filtrelemesi → `Temporary failure resolving` | Geçici DHCP'ye geçilip araçlar kuruldu, sonra gateway IP'si (172.19.224.1) DNS olarak atandı |
| PEP 668 `externally-managed-environment` (slowloris) | `pip install --break-system-packages` (yalnızca saldırgan makine — tek kullanımlık ortam) |
| `slowloris` PATH'te değil | `~/.local/bin` `.bashrc`'ye export edildi |

## Mimari Konum

```
[SimVM-Normal]      [SimVM-Attacker]
 172.19.237.100      172.19.237.200
      │                    │
      └────────┬───────────┘
               │  (Bridged ağ / saldırı trafiği)
               ▼
        [Host PC / Raspberry Pi 4]
         HIDS: Scapy + XGBoost + Dashboard
```

## Sonraki Adım

- Saldırı senaryolarının betiklenmesi (FR-01.2): nmap, hping3, hydra, slowloris
- Normal trafik üreticisinin kurulması (FR-01.1): sürekli HTTP/DNS/FTP trafiği
- HIDS paket yakalama motorunun host/Pi üzerinde devreye alınması (FR-02)
