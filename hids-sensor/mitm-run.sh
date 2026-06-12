#!/bin/bash
# ============================================================
#  HIDS Sensör — Inline (ARP MITM) Modu
#  Pi'yi saldırgan<->kurban arasına sokar, aradan geçen
#  trafiği yakalar ve buluta push eder.
#
#  Kullanım (Pi üzerinde, root):
#    sudo bash mitm-run.sh [KURBAN_IP] [SALDIRGAN_IP]
#  Varsayılan IP'ler aşağıda. Ctrl+C ile temiz çıkış (ARP geri yüklenir).
# ============================================================
set -e

VICTIM="${1:-192.168.137.198}"     # simvm-normal (kurban / hedef)
ATTACKER="${2:-192.168.137.139}"   # simvm-attacker (saldırgan)
RELAY="wss://hids-xgboost-shap-slm.onrender.com/ingest"
INSTALL_DIR="/opt/hids-sensor"

if [ "$EUID" -ne 0 ]; then
    echo "[HATA] sudo ile çalıştırın: sudo bash mitm-run.sh"
    exit 1
fi

# Pi'nin 192.168.137.x adresli arayüzünü otomatik bul (eth0 veya wlan0)
IFACE=$(ip -o -4 addr show | awk '/192\.168\.137\./{print $2; exit}')
if [ -z "$IFACE" ]; then
    echo "[HATA] 192.168.137.x arayüzü bulunamadı. 'ip a' ile kontrol edin."
    exit 1
fi

echo "============================================"
echo "  HIDS Inline (ARP MITM)"
echo "  Arayüz:    $IFACE"
echo "  Kurban:    $VICTIM"
echo "  Saldırgan: $ATTACKER"
echo "  Relay:     $RELAY"
echo "============================================"

# arpspoof (dsniff) kurulu değilse kur
if ! command -v arpspoof >/dev/null 2>&1; then
    echo "[*] dsniff (arpspoof) kuruluyor..."
    apt-get update -qq && apt-get install -y -qq dsniff
fi

# IP forwarding aç — kurban erişilebilir kalsın, bağlantı kopmasın
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Çıkışta ARP tablolarını geri yükle + forwarding kapat
cleanup() {
    echo ""
    echo "[*] Temizleniyor (ARP geri yükleniyor)..."
    kill "$ARP_PID" 2>/dev/null || true
    sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# Çift yönlü ARP zehirleme (-r = bidirectional, tek process)
echo "[*] ARP MITM başlatılıyor..."
arpspoof -i "$IFACE" -t "$VICTIM" -r "$ATTACKER" >/dev/null 2>&1 &
ARP_PID=$!
sleep 2
echo "[*] ARP MITM aktif (pid $ARP_PID)."

# Sensörü başlat — yalnızca iki host arasındaki trafiği yakala
cd "$INSTALL_DIR"
echo "[*] Sensör başlatılıyor (Ctrl+C ile durdur)..."
sensor/venv/bin/python sensor/app.py \
    --iface "$IFACE" \
    --bpf "host $VICTIM and host $ATTACKER" \
    --models models \
    --relay "$RELAY"
