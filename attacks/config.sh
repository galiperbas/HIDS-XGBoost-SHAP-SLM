# shellcheck shell=bash
# =============================================================================
# config.sh — Saldırı betikleri için ortak yapılandırma ve yardımcılar.
# Tüm betikler bunu `source` eder. Tek başına çalıştırılmaz.
#
# Hedef makine = SimVM-Normal (kurban).  Saldırgan = SimVM-Attacker.
# IP'leri ortam değişkeniyle geçici olarak ezebilirsiniz:
#     TARGET=192.168.137.50 ./01_port_scan.sh
# =============================================================================

# --- Ağ ---------------------------------------------------------------------
TARGET="${TARGET:-192.168.137.238}"      # SimVM-Normal  (kurban / hedef)
ATTACKER_IP="${ATTACKER_IP:-192.168.137.61}"  # SimVM-Attacker (bu makine)
IFACE="${IFACE:-ens33}"                   # saldırgan VM çıkış arayüzü

# --- Wordlist'ler (brute force) --------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USERLIST="${USERLIST:-$SCRIPT_DIR/wordlists/users.txt}"
PASSLIST="${PASSLIST:-$SCRIPT_DIR/wordlists/passwords.txt}"

# --- Renkli çıktı -----------------------------------------------------------
if [ -t 1 ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
  C_BLU=$'\033[34m'; C_BOLD=$'\033[1m'; C_RST=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_BOLD=""; C_RST=""
fi

# banner "Başlık" "HIDS'te beklenen etiket"
banner() {
  echo
  echo "${C_BOLD}${C_BLU}=== $1 ===${C_RST}"
  echo "${C_BLU}Hedef:${C_RST} $TARGET   ${C_BLU}Kaynak:${C_RST} $ATTACKER_IP"
  [ -n "${2:-}" ] && echo "${C_BLU}Beklenen HIDS etiketi:${C_RST} ${C_BOLD}$2${C_RST}"
  echo
}

# require_tool nmap  → yoksa kurulum ipucuyla çıkar
require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "${C_RED}[HATA]${C_RST} '$1' bulunamadı. Kur:  sudo apt install -y $1" >&2
    exit 127
  fi
}

# need_root → raw socket gerektiren betikleri sudo ile yeniden başlatır
need_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "${C_YEL}[bilgi]${C_RST} Bu saldırı root yetkisi ister; sudo ile yeniden başlatılıyor..."
    exec sudo -E "$0" "$@"
  fi
}

# ping_check → hedefe erişimi doğrular (bağlantı testi)
ping_check() {
  if ping -c1 -W2 "$TARGET" >/dev/null 2>&1; then
    echo "${C_GRN}[ok]${C_RST} Hedef $TARGET erişilebilir."
  else
    echo "${C_YEL}[uyarı]${C_RST} Hedef $TARGET ping'e yanıt vermiyor (ICMP kapalı olabilir; saldırı yine de denenebilir)."
  fi
}

# countdown 3 → "3.. 2.. 1.." geri sayım
countdown() {
  local n="${1:-3}"
  printf "Başlıyor: "
  while [ "$n" -gt 0 ]; do printf "%d.. " "$n"; sleep 1; n=$((n-1)); done
  echo
}
