#!/bin/bash
# ============================================================
#  HIDS Sensör — Raspberry Pi 4 Otomatik Kurulum
#  Kullanım: sudo bash pi-setup.sh
# ============================================================
set -e

echo "=========================================="
echo "  HIDS Sensör — Raspberry Pi 4 Kurulum"
echo "=========================================="

# Root kontrolü
if [ "$EUID" -ne 0 ]; then
    echo "[HATA] Bu scripti sudo ile çalıştırın: sudo bash pi-setup.sh"
    exit 1
fi

INSTALL_DIR="/opt/hids-sensor"
HIDS_USER="pi"  # Pi'deki kullanıcı adı

# ── 1. Sistem paketleri ──
echo ""
echo "[1/5] Sistem paketleri güncelleniyor..."
apt-get update -qq
apt-get install -y -qq \
    python3 python3-pip python3-venv \
    libpcap-dev tcpdump \
    git curl

# Pi kullanıcısına paket yakalama izni ver (sudo gerekmeden)
echo "[+] Paket yakalama izni ayarlanıyor..."
groupadd -f pcap
usermod -aG pcap "$HIDS_USER" 2>/dev/null || true
chgrp pcap /usr/bin/tcpdump 2>/dev/null || true
setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump 2>/dev/null || true

# ── 2. Kurulum dizini ──
echo ""
echo "[2/5] Kurulum dizini oluşturuluyor: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR/models"
mkdir -p "$INSTALL_DIR/sensor"
mkdir -p "$INSTALL_DIR/logs"

# ── 3. Python sanal ortam ──
echo ""
echo "[3/5] Python sanal ortam oluşturuluyor..."
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"

# ── 4. Python bağımlılıkları ──
echo ""
echo "[4/5] Python bağımlılıkları kuruluyor..."
pip install --upgrade pip -q

# Pi için requirements (scapy Linux'ta libpcap kullanır, Npcap gerekmez)
pip install -q \
    fastapi==0.115.6 \
    "uvicorn[standard]==0.30.6" \
    scapy==2.6.1 \
    joblib==1.4.2 \
    xgboost==2.1.3 \
    scikit-learn==1.6.1 \
    numpy==1.26.4 \
    websocket-client==1.8.0
# NOT: scikit-learn ŞART — model joblib ile yüklenirken XGBClassifier sarmalayıcısı
# ve RobustScaler sklearn'e ihtiyaç duyar. Eksikse XGBoost yüklenemez, sadece kural
# katmanı çalışır.

deactivate

# ── 5. Systemd servisi ──
echo ""
echo "[5/5] Systemd servisi oluşturuluyor..."

cat > /etc/systemd/system/hids-sensor.service << 'UNIT'
[Unit]
Description=HIDS Sensor — Hybrid Detection (XGBoost + Rule-based)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/hids-sensor
ExecStart=/opt/hids-sensor/run.sh
Restart=on-failure
RestartSec=5
StandardOutput=append:/opt/hids-sensor/logs/sensor.log
StandardError=append:/opt/hids-sensor/logs/sensor.log

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload

# ── Özet ──
echo ""
echo "=========================================="
echo "  Kurulum Tamamlandı!"
echo "=========================================="
echo ""
echo "Sonraki adımlar:"
echo "  1. Bilgisayardan dosyaları kopyalayın (SCP ile)"
echo "  2. /opt/hids-sensor/run.sh dosyasını düzenleyin (ağ ayarları)"
echo "  3. Servisi başlatın:"
echo "     sudo systemctl start hids-sensor"
echo "     sudo systemctl enable hids-sensor  # açılışta otomatik"
echo ""
echo "Log izleme:"
echo "  sudo journalctl -u hids-sensor -f"
echo "  tail -f /opt/hids-sensor/logs/sensor.log"
echo ""
