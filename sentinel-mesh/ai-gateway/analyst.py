"""
analyst.py — Agentic SOC Analyst (tezdeki SLM bileşeninin gerçeklenmesi).

Bir HIDS tespitini (kural/XGBoost/promptguard çıktısı) alır ve bir SOC analistinin
yapacağı triyajı üretir:
  - doğal dilde özet ("ne oldu, neden tehlikeli")
  - OWASP LLM Top 10 / MITRE ATT&CK eşlemesi
  - önerilen müdahale adımları
  - yanlış-pozitif olasılığı

İki çalışma modu (otomatik seçilir):
  1. ANTHROPIC_API_KEY varsa  -> Claude (claude-opus-4-8) ile gerçek muhakeme.
  2. Anahtar yoksa / SDK yoksa -> deterministik şablon (promptguard kanıtlarından).
     Bu sayede demo, internet/anahtar olmadan da ÇALIŞIR; anahtar gelince
     otomatik olarak gerçek LLM analizine yükselir.

Mimari not: Bu, "agentic SOC analyst" katmanıdır — tespit motoru (promptguard,
XGBoost) ham sinyali üretir; analist katmanı onu insan-anlaşılır istihbarata
ve aksiyona çevirir. Bkz. gateway.py, [[promptguard.py]].
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional

MODEL = os.environ.get("ANALYST_MODEL", "claude-opus-4-8")

try:
    import anthropic
except ImportError:
    anthropic = None


# Analist çıktısının yapısı (structured output şeması)
_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "owasp": {"type": "string"},
        "mitre_attack": {"type": "array", "items": {"type": "string"}},
        "recommended_actions": {"type": "array", "items": {"type": "string"}},
        "false_positive_likelihood": {"type": "string", "enum": ["low", "medium", "high"]},
    },
    "required": ["summary", "severity", "owasp", "mitre_attack",
                 "recommended_actions", "false_positive_likelihood"],
    "additionalProperties": False,
}

_SYSTEM = (
    "You are an autonomous SOC (Security Operations Center) analyst agent embedded "
    "in a host-based intrusion detection system that protects an AI/LLM service. "
    "You receive a single detection event (from rule-based, XGBoost, or prompt-injection "
    "detectors) and produce a concise triage. Map findings to the OWASP LLM Top 10 and "
    "MITRE ATT&CK where applicable. Be precise and operational — a tier-1 analyst should be "
    "able to act on your output immediately. Do not speculate beyond the evidence provided. "
    "Respond in Turkish."
)


def analyze(event: dict, guard_result: Optional[dict] = None,
            max_tokens: int = 1200) -> dict:
    """
    Bir tespit olayını analiz eder ve yapılandırılmış analist triyajı döndürür.

    Args:
        event: dashboard olay sözlüğü (attack_type, threat_score, source_ip, ...).
        guard_result: promptguard.GuardResult.to_dict() (varsa — kanıt/kurallar).

    Returns:
        dict: {summary, severity, owasp, mitre_attack[], recommended_actions[],
               false_positive_likelihood, engine}
    """
    if anthropic is not None and os.environ.get("ANTHROPIC_API_KEY"):
        try:
            return _claude_analyze(event, guard_result, max_tokens)
        except Exception as e:  # ağ/oran/anahtar sorunlarında sessizce fallback
            out = _fallback(event, guard_result)
            out["engine"] = f"fallback (claude hatası: {type(e).__name__})"
            return out
    return _fallback(event, guard_result)


def _claude_analyze(event: dict, guard_result: Optional[dict], max_tokens: int) -> dict:
    client = anthropic.Anthropic()  # ANTHROPIC_API_KEY ortamdan okunur

    payload = {"detection": event}
    if guard_result:
        payload["prompt_guard"] = guard_result

    user_msg = (
        "Aşağıdaki HIDS tespitini bir SOC analisti gibi triyaj et. "
        "Kanıt (prompt_guard.hits) varsa gerekçende ona atıf yap.\n\n"
        + json.dumps(payload, ensure_ascii=False, indent=2)
    )

    resp = client.messages.create(
        model=MODEL,
        max_tokens=max_tokens,
        system=_SYSTEM,
        thinking={"type": "adaptive"},
        output_config={"format": {"type": "json_schema", "schema": _SCHEMA}},
        messages=[{"role": "user", "content": user_msg}],
    )

    text = next((b.text for b in resp.content if b.type == "text"), "{}")
    data = json.loads(text)
    data["engine"] = f"claude:{MODEL}"
    return data


# ── Deterministik fallback (LLM yokken) ──
_MITRE_MAP = {
    "LLM_PromptInjection": ["T1059 (Command and Scripting)", "T1566 (Phishing/Injection)"],
    "LLM_DataExfil": ["T1041 (Exfiltration Over C2)", "T1005 (Data from Local System)"],
    "LLM_SystemPromptLeak": ["T1592 (Gather Victim Host Info)"],
    "SYN_Flood": ["T1498 (Network Denial of Service)"],
    "DoS_Flood": ["T1498 (Network Denial of Service)"],
    "PortScan": ["T1046 (Network Service Discovery)"],
    "BruteForce": ["T1110 (Brute Force)"],
    "ML_Detected": ["T1190 (Exploit Public-Facing Application)"],
}
_OWASP_MAP = {
    "LLM_PromptInjection": "LLM01: Prompt Injection",
    "LLM_DataExfil": "LLM02: Sensitive Information Disclosure",
    "LLM_SystemPromptLeak": "LLM07: System Prompt Leakage",
}
_ACTIONS = {
    "LLM_PromptInjection": [
        "İsteği engelle ve kaynak IP'yi geçici karantinaya al.",
        "AI servisinin sistem prompt'unun sızmadığını doğrula.",
        "Aynı oturumdan gelen önceki istekleri incele (kampanya mı?).",
    ],
    "LLM_DataExfil": [
        "Yanıtın gizli veri (anahtar/PII) içermediğini doğrula.",
        "İlgili kimlik bilgilerini rotasyona al.",
        "DLP kurallarını ve çıkış (egress) loglarını gözden geçir.",
    ],
    "LLM_SystemPromptLeak": [
        "Sistem prompt'unun açığa çıkıp çıkmadığını denetle.",
        "Prompt sızdırmaya karşı çıktı filtresini sıkılaştır.",
    ],
}


def _fallback(event: dict, guard_result: Optional[dict]) -> dict:
    atype = event.get("attack_type", "BENIGN")
    score = int(event.get("threat_score", 0) or 0)
    src = event.get("source_ip", "?")
    dst = event.get("destination_ip", "?")

    severity = ("critical" if score >= 85 else "high" if score >= 70
                else "medium" if score >= 35 else "low")

    reasons = ""
    if guard_result and guard_result.get("hits"):
        top = guard_result["hits"][0]
        reasons = f" Tetikleyen kanıt: [{top.get('owasp')}/{top.get('rule_id')}] " \
                  f"\"{top.get('snippet', '')[:60]}\"."

    owasp = _OWASP_MAP.get(atype, event.get("owasp", "—"))
    summary = (f"{src} kaynağından {dst} hedefindeki AI servisine yönelik {atype} "
               f"tespiti (tehdit skoru {score}).{reasons}")

    return {
        "summary": summary,
        "severity": severity,
        "owasp": owasp,
        "mitre_attack": _MITRE_MAP.get(atype, ["—"]),
        "recommended_actions": _ACTIONS.get(
            atype, ["Olayı analiste yükselt ve kaynak IP davranışını izle."]),
        "false_positive_likelihood": "low" if score >= 70 else "medium",
        "engine": "fallback (deterministik)",
    }


if __name__ == "__main__":
    demo_event = {
        "attack_type": "LLM_PromptInjection", "threat_score": 92,
        "source_ip": "192.168.137.139", "destination_ip": "192.168.137.198",
    }
    demo_guard = {"hits": [{"owasp": "LLM01", "rule_id": "INSTR_OVERRIDE",
                            "snippet": "ignore all previous instructions"}]}
    print(json.dumps(analyze(demo_event, demo_guard), ensure_ascii=False, indent=2))
