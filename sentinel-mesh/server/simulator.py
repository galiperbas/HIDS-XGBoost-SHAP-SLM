"""
simulator.py — Demo veri üreteci (Pi bağlı değilken yedek).

Pi bağlandığında (sensor_count > 0) otomatik durur.
Gerçekçi saldırı senaryoları üretir:
- %60 normal trafik, %40 saldırı
- 7 saldırı tipi (DDoS, DoS, Recon, BruteForce, Spoofing, Mirai, WebAttack)
- Gerçekçi IP'ler, portlar, threat score'lar
- SHAP benzeri 'neden' açıklamaları
"""

import asyncio
import random
import time
from datetime import datetime

# Simüle edilmiş ağ yapısı
NORMAL_IPS = ["192.168.238.100", "192.168.238.101", "192.168.238.102", "10.0.0.50", "10.0.0.51"]
ATTACKER_IPS = ["192.168.238.200", "45.33.32.156", "185.220.101.34", "23.129.64.210"]
TARGET_IPS = ["192.168.238.100", "192.168.238.101", "10.0.0.50"]

ATTACK_SCENARIOS = [
    {
        "attack_type": "PortScan",
        "method": "rule",
        "threat_score_range": (60, 95),
        "confidence_range": (0.88, 0.96),
        "protocols": ["TCP", "SYN"],
        "dst_ports": [22, 80, 443, 445, 3389, 8080, 21, 23, 25, 3306],
        "reason": "Son 1 saniyede {ports} farklı port tarandı",
    },
    {
        "attack_type": "SYN_Flood",
        "method": "rule",
        "threat_score_range": (75, 99),
        "confidence_range": (0.92, 0.99),
        "protocols": ["TCP"],
        "dst_ports": [80, 443, 8080],
        "reason": "Saniyede {count} SYN paketi — bağlantı tüketme saldırısı",
    },
    {
        "attack_type": "DoS_Flood",
        "method": "rule",
        "threat_score_range": (65, 98),
        "confidence_range": (0.85, 0.95),
        "protocols": ["UDP", "ICMP"],
        "dst_ports": [53, 123, 161],
        "reason": "Yoğun paket akışı ({pps} paket/sn) — hizmet dışı bırakma girişimi",
    },
    {
        "attack_type": "BruteForce",
        "method": "rule",
        "threat_score_range": (60, 90),
        "confidence_range": (0.82, 0.93),
        "protocols": ["SSH", "FTP"],
        "dst_ports": [22, 21],
        "reason": "SSH/FTP oturumuna {count} başarısız giriş denemesi",
    },
    {
        "attack_type": "DDoS_HTTP",
        "method": "xgboost",
        "threat_score_range": (70, 99),
        "confidence_range": (0.90, 0.99),
        "protocols": ["HTTP", "HTTPS"],
        "dst_ports": [80, 443, 8080],
        "reason": "XGBoost: Anormal HTTP istek paterni — dağıtık saldırı şüphesi",
    },
    {
        "attack_type": "Mirai_Botnet",
        "method": "xgboost",
        "threat_score_range": (80, 99),
        "confidence_range": (0.93, 0.99),
        "protocols": ["TCP", "Telnet"],
        "dst_ports": [23, 2323, 48101],
        "reason": "XGBoost: Mirai imzası — IoT cihaz ele geçirme girişimi",
    },
    {
        "attack_type": "Recon_Scan",
        "method": "xgboost",
        "threat_score_range": (40, 75),
        "confidence_range": (0.78, 0.92),
        "protocols": ["ICMP", "TCP"],
        "dst_ports": [0, 7, 13, 37],
        "reason": "XGBoost: Keşif taraması — ağ haritalama davranışı",
    },
]


def _status_label(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    elif score >= 35:
        return "MEDIUM"
    return "SAFE"


def generate_normal_event(event_id: int) -> dict:
    """Normal (benign) trafik olayı üret."""
    src = random.choice(NORMAL_IPS)
    dst = random.choice([ip for ip in NORMAL_IPS if ip != src] or NORMAL_IPS)
    proto = random.choice(["HTTP", "HTTPS", "DNS", "TCP", "UDP"])
    port = random.choice([80, 443, 53, 22, 8080, 3000])
    return {
        "id": str(event_id),
        "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "source_ip": src,
        "destination_ip": dst,
        "protocol": proto,
        "threat_score": random.randint(0, 15),
        "status": "SAFE",
        "label": "NORMAL",
        "attack_type": "BENIGN",
        "method": random.choice(["rule", "xgboost"]),
        "confidence": round(random.uniform(0.95, 0.99), 3),
        "flow_packets": random.randint(1, 20),
    }


def generate_attack_event(event_id: int) -> dict:
    """Saldırı olayı üret."""
    scenario = random.choice(ATTACK_SCENARIOS)
    src = random.choice(ATTACKER_IPS)
    dst = random.choice(TARGET_IPS)
    score = random.randint(*scenario["threat_score_range"])
    ports = random.randint(15, 50)
    count = random.randint(30, 200)
    pps = random.randint(100, 500)
    
    return {
        "id": str(event_id),
        "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "source_ip": src,
        "destination_ip": dst,
        "protocol": random.choice(scenario["protocols"]),
        "threat_score": score,
        "status": _status_label(score),
        "label": "ANOMALY",
        "attack_type": scenario["attack_type"],
        "method": scenario["method"],
        "confidence": round(random.uniform(*scenario["confidence_range"]), 3),
        "flow_packets": random.randint(10, 200),
        "reason": scenario["reason"].format(ports=ports, count=count, pps=pps),
    }


def generate_event(event_id: int) -> dict:
    """Rastgele olay üret (%60 normal, %40 saldırı)."""
    if random.random() < 0.4:
        return generate_attack_event(event_id)
    return generate_normal_event(event_id)
