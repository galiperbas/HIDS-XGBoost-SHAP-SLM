#!/bin/bash
# ============================================================
#  HIDS Sensör — Raspberry Pi Başlatma Scripti
#  Kullanım: sudo bash /opt/hids-sensor/run.sh
# ============================================================

# ── Ayarlar (kendi ağınıza göre düzenleyin) ──

# Raspberry Pi'nin dinleyeceği ağ arayüzü
# "eth0" = Ethernet (bilgisayara kablolu bağlantı)
# Listelemek için: ip link show
IFACE="eth0"

# VM IP adresleri (hedef ve saldırgan)
TARGET_IP="192.168.238.100"
ATTACKER_IP="192.168.238.200"

# BPF filtre — sadece VM'ler arası trafiği yakala
BPF_FILTER="host ${TARGET_IP} or host ${ATTACKER_IP}"

# Relay sunucu (Render'daki canlı sunucu)
RELAY_URL="wss://hids-xgboost-shap-slm.onrender.com/ingest"

# Sensör API portu (Pi üzerinde, opsiyonel lokal dashboard)
PORT=8000

# Model dizini
MODELS_DIR="/opt/hids-sensor/models"

# ── Başlat ──
INSTALL_DIR="/opt/hids-sensor"
cd "$INSTALL_DIR"

echo "============================================"
echo "  HIDS Sensör — Raspberry Pi 4"
echo "============================================"
echo "  Arayüz:    $IFACE"
echo "  Hedef:     $TARGET_IP"
echo "  Saldırgan: $ATTACKER_IP"
echo "  BPF:       $BPF_FILTER"
echo "  Relay:     $RELAY_URL"
echo "  Port:      $PORT"
echo "============================================"

# IP forwarding aktif et (Pi'nin trafiği görmesi için)
echo 1 > /proc/sys/net/ipv4/ip_forward

# Sanal ortamı aktif et
source "$INSTALL_DIR/venv/bin/activate"

# Sensörü başlat
exec python3 "$INSTALL_DIR/sensor/app.py" \
    --iface "$IFACE" \
    --bpf "$BPF_FILTER" \
    --models "$MODELS_DIR" \
    --relay "$RELAY_URL" \
    --port "$PORT"
