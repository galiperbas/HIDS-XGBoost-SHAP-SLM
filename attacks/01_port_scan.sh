#!/usr/bin/env bash
# =============================================================================
# 01_port_scan.sh — nmap ile port taraması.
#
# HIDS kuralı:  unique_ports_last_sec >= 15  →  PortScan
# nmap SYN taraması saniyede onlarca farklı porta SYN gönderir; tek kaynaktan
# 15+ benzersiz hedef port eşiği kolayca aşılır → "PortScan" alarmı.
#
# NOT: SYN taraması (-sS) raw socket ister (root). Root değilseniz betik
# otomatik olarak TCP connect taramasına (-sT) düşer.
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/config.sh"
require_tool nmap

banner "Port Scan (nmap)" "PortScan"
ping_check

if [ "${EUID:-$(id -u)}" -eq 0 ]; then
  SCAN="-sS"   # SYN (yarı-açık) tarama — hızlı, root gerektirir
  echo "[mod] SYN taraması (-sS)"
else
  SCAN="-sT"   # connect taraması — root gerekmez, biraz daha yavaş
  echo "[mod] connect taraması (-sT)  (root değilsiniz; -sS için: sudo $0)"
fi

countdown 3
# -T4: agresif zamanlama, --min-rate: saniyede en az 500 paket → eşiği garantiler
nmap $SCAN -T4 --min-rate 500 -p 1-1000 "$TARGET"

echo
echo "${C_GRN}[bitti]${C_RST} Port taraması tamamlandı. HIDS panosunda 'PortScan' görmelisiniz."
