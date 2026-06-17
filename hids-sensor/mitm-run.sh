#!/bin/bash
# ============================================================
#  HIDS Sensör — Inline (ARP MITM) Modu  [sağlamlaştırılmış]
#  Pi'yi saldırgan<->kurban arasına sokar, aradan geçen trafiği
#  yakalar ve buluta push eder.
#
#  Kullanım (Pi üzerinde, root):
#    sudo bash mitm-run.sh <KURBAN_IP> <SALDIRGAN_IP>
#  Örnek:
#    sudo bash mitm-run.sh 192.168.137.26 192.168.137.177
#
#  Ctrl+C ile temiz çıkış (ARP geri yüklenir, forwarding eski haline döner).
#  NOT: ARP-MITM yalnızca KENDİ İZOLE LABORATUVARINDA meşrudur.
#
#  Bu sürümde eklenenler (çalışan çekirdek DEĞİŞMEDİ):
#   - Argüman doğrulaması (zorunlu + geçerli IPv4 + farklı + Pi'nin kendisi değil)
#   - MITM başlatma doğrulaması (arpspoof gerçekten ayakta mı?)
#   - arpspoof çıktısı log'lanır (artık /dev/null'a atılıp gizlenmez)
#   - ip_forward'ın ESKİ değeri saklanır ve çıkışta geri yüklenir
#   - Çıkışta arpspoof'a ARP düzeltme paketlerini yollaması için 'wait'
# ============================================================
set -e

VICTIM="${1:-}"
ATTACKER="${2:-}"
RELAY="${RELAY:-wss://hids-xgboost-shap-slm.onrender.com/ingest}"
INSTALL_DIR="/opt/hids-sensor"
ARP_LOG="/tmp/hids_arpspoof.log"
SETTLE="${SETTLE:-3}"          # ARP'in oturması için bekleme (sn)

log() { echo "[*] $*"; }
err() { echo "[HATA] $*" >&2; }
usage() { echo "Kullanım: sudo bash mitm-run.sh <KURBAN_IP> <SALDIRGAN_IP>" >&2; }

# ── 0. Root kontrolü ──
if [ "$EUID" -ne 0 ]; then
    err "sudo ile çalıştırın."
    usage
    exit 1
fi

# ── 1. Argüman doğrulaması (bayat varsayılan IP kullanılmaz) ──
if [ -z "$VICTIM" ] || [ -z "$ATTACKER" ]; then
    err "Kurban ve saldırgan IP'leri ZORUNLUDUR."
    usage
    exit 1
fi

is_ipv4() {
    local ip="$1" o
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1}"; do
        [ "$o" -le 255 ] || return 1
    done
    return 0
}

if ! is_ipv4 "$VICTIM";   then err "Geçersiz kurban IP: '$VICTIM'";     usage; exit 1; fi
if ! is_ipv4 "$ATTACKER"; then err "Geçersiz saldırgan IP: '$ATTACKER'"; usage; exit 1; fi
if [ "$VICTIM" = "$ATTACKER" ]; then
    err "Kurban ve saldırgan aynı IP olamaz: $VICTIM"
    exit 1
fi

# ── 2. Pi'nin 192.168.137.x arayüzü ve kendi IP'si ──
# (Arayüz tespiti orijinaldeki ile AYNI awk mantığı — kanıtlanmış davranış.)
IFACE=$(ip -o -4 addr show | awk '/192\.168\.137\./{print $2; exit}')
SELF_IP=$(ip -o -4 addr show | awk '/192\.168\.137\./{split($4,a,"/"); print a[1]; exit}')

if [ -z "$IFACE" ]; then
    err "192.168.137.x arayüzü bulunamadı. 'ip a' ile kontrol edin."
    exit 1
fi
if [ "$VICTIM" = "$SELF_IP" ] || [ "$ATTACKER" = "$SELF_IP" ]; then
    err "Hedeflerden biri Pi'nin kendi IP'si ($SELF_IP). Kurban/saldırgan IP'lerini kontrol edin."
    exit 1
fi

echo "============================================"
echo "  HIDS Inline (ARP MITM)"
echo "  Arayüz:    $IFACE  (Pi: ${SELF_IP:-?})"
echo "  Kurban:    $VICTIM"
echo "  Saldırgan: $ATTACKER"
echo "  Relay:     $RELAY"
echo "============================================"

# ── 3. Bağımlılık + erişilebilirlik ön kontrolü ──
if ! command -v arpspoof >/dev/null 2>&1; then
    log "dsniff (arpspoof) kuruluyor..."
    apt-get update -qq && apt-get install -y -qq dsniff
fi

# Erişim kontrolü yalnızca BİLGİ amaçlı: ICMP kapalı olabilir → demoyu ENGELLEMEZ.
for host in "$VICTIM" "$ATTACKER"; do
    if ping -c1 -W1 "$host" >/dev/null 2>&1; then
        log "Erişim OK: $host"
    else
        echo "[uyarı] $host ping'e yanıt vermiyor (ICMP kapalı olabilir; devam ediliyor)."
    fi
done

# ── 4. IP forwarding (ESKİ değeri sakla, çıkışta geri yükle) ──
ORIG_FWD="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)"
sysctl -w net.ipv4.ip_forward=1 >/dev/null
if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" != "1" ]; then
    err "IP forwarding açılamadı — kurban bağlantısı kopabilir. İptal."
    exit 1
fi

# ── 5. Temiz çıkış (ARP geri yükle, forwarding'i ESKİ haline al) ──
ARP_PID=""
cleanup() {
    echo ""
    log "Temizleniyor (ARP geri yükleniyor, forwarding eski haline alınıyor)..."
    if [ -n "$ARP_PID" ]; then
        kill "$ARP_PID" 2>/dev/null || true
        wait "$ARP_PID" 2>/dev/null || true   # arpspoof'un ARP düzeltmesini bitirmesini bekle
    fi
    sysctl -w net.ipv4.ip_forward="$ORIG_FWD" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# ── 6. Çift yönlü ARP zehirleme + BAŞLATMA DOĞRULAMASI ──
log "ARP MITM başlatılıyor..."
: > "$ARP_LOG"
arpspoof -i "$IFACE" -t "$VICTIM" -r "$ATTACKER" >>"$ARP_LOG" 2>&1 &
ARP_PID=$!

sleep "$SETTLE"

# (a) arpspoof gerçekten ayakta mı? Hedef MAC çözülemezse arpspoof hemen çıkar.
if ! kill -0 "$ARP_PID" 2>/dev/null; then
    err "arpspoof başlatılamadı/çöktü (hedef MAC çözülemedi olabilir). Son satırlar:"
    tail -n 5 "$ARP_LOG" >&2 || true
    err "Kurban/saldırgan IP'leri ve aynı L2 ağda olduklarını doğrulayın."
    exit 1
fi
# (b) Yumuşak kontrol: arpspoof ARP paketi yolladığına dair iz bıraktı mı?
if ! grep -q ':' "$ARP_LOG" 2>/dev/null; then
    echo "[uyarı] arpspoof henüz ARP paketi loglamadı; MITM tam oturmamış olabilir (devam)."
fi
log "ARP MITM aktif (pid $ARP_PID).  Tanı için: tail -f $ARP_LOG"

# ── 7. Sensörü başlat (DEĞİŞMEDİ — aynı arayüz/bpf/model/relay) ──
cd "$INSTALL_DIR"
log "Sensör başlatılıyor (Ctrl+C ile durdur)..."
sensor/venv/bin/python sensor/app.py \
    --iface "$IFACE" \
    --bpf "host $VICTIM and host $ATTACKER" \
    --models models \
    --relay "$RELAY"
