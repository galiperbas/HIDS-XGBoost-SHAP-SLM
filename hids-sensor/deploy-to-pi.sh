#!/bin/bash
# ============================================================
#  Dosyaları Raspberry Pi'ye Kopyala (Windows Git Bash / WSL)
#  Kullanım: bash deploy-to-pi.sh [PI_IP] [PI_USER]
# ============================================================

PI_IP="${1:-192.168.1.100}"    # Pi'nin IP adresi (varsayılan)
PI_USER="${2:-pi}"             # Pi kullanıcı adı

REMOTE_DIR="/opt/hids-sensor"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=========================================="
echo "  HIDS Sensör → Raspberry Pi Deploy"
echo "=========================================="
echo "  Pi:   ${PI_USER}@${PI_IP}"
echo "  Hedef: ${REMOTE_DIR}"
echo ""

# 1. Pi'de dizinleri oluştur (hedef + scp için geçici /tmp dizinleri)
echo "[1/4] Pi'de dizinler oluşturuluyor..."
ssh "${PI_USER}@${PI_IP}" "sudo mkdir -p ${REMOTE_DIR}/sensor ${REMOTE_DIR}/models ${REMOTE_DIR}/logs && mkdir -p /tmp/hids_sensor /tmp/hids_models"

# 2. Sensör kodlarını kopyala
echo "[2/4] Sensör kodları kopyalanıyor..."
scp "${SCRIPT_DIR}/sensor/sniffer.py" \
    "${SCRIPT_DIR}/sensor/flow_aggregator.py" \
    "${SCRIPT_DIR}/sensor/detector.py" \
    "${SCRIPT_DIR}/sensor/sysmetrics.py" \
    "${SCRIPT_DIR}/sensor/incident_aggregator.py" \
    "${SCRIPT_DIR}/sensor/app.py" \
    "${PI_USER}@${PI_IP}:/tmp/hids_sensor/"

# cloud_push.py'yi de sensör dizinine kopyala
scp "${PROJECT_DIR}/sentinel-mesh/server/cloud_push.py" \
    "${PI_USER}@${PI_IP}:/tmp/hids_sensor/"

ssh "${PI_USER}@${PI_IP}" "sudo cp /tmp/hids_sensor/* ${REMOTE_DIR}/sensor/"

# 3. Model dosyalarını kopyala
echo "[3/4] XGBoost modeli kopyalanıyor..."
scp "${PROJECT_DIR}/models/xgboost_ciciot2023.joblib" \
    "${PROJECT_DIR}/models/scaler.joblib" \
    "${PROJECT_DIR}/models/feature_names.json" \
    "${PROJECT_DIR}/models/model_meta.json" \
    "${PI_USER}@${PI_IP}:/tmp/hids_models/"

ssh "${PI_USER}@${PI_IP}" "sudo cp /tmp/hids_models/* ${REMOTE_DIR}/models/"

# 4. Scriptleri kopyala
echo "[4/4] Çalıştırma scriptleri kopyalanıyor..."
scp "${SCRIPT_DIR}/pi-setup.sh" \
    "${SCRIPT_DIR}/run.sh" \
    "${SCRIPT_DIR}/mitm-run.sh" \
    "${PI_USER}@${PI_IP}:/tmp/"

ssh "${PI_USER}@${PI_IP}" "sudo cp /tmp/pi-setup.sh /tmp/run.sh /tmp/mitm-run.sh ${REMOTE_DIR}/ && sudo chmod +x ${REMOTE_DIR}/*.sh"

echo ""
echo "=========================================="
echo "  Kopyalama Tamamlandı!"
echo "=========================================="
echo ""
echo "Şimdi Pi'ye SSH ile bağlanın ve kurulumu çalıştırın:"
echo "  ssh ${PI_USER}@${PI_IP}"
echo "  sudo bash ${REMOTE_DIR}/pi-setup.sh"
echo ""
echo "Kurulumdan sonra sensörü başlatın:"
echo "  sudo bash ${REMOTE_DIR}/run.sh"
echo ""
echo "Veya systemd ile:"
echo "  sudo systemctl start hids-sensor"
echo ""
