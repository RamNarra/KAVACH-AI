"""
MITRE ATT&CK Mobile technique tagging for Kavach AI findings.
"""

from typing import Any, Dict, List

import os
import json
import logging

logger = logging.getLogger("kavach-attack")

# id -> {name, tactic}
TECHNIQUES: Dict[str, Dict[str, str]] = {}

def load_mitre_techniques():
    global TECHNIQUES
    base_dir = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(base_dir, "tools", "mitre_mobile.json")
    if os.path.exists(json_path):
        try:
            with open(json_path, "r") as f:
                TECHNIQUES.update(json.load(f))
            logger.info(f"Loaded {len(TECHNIQUES)} MITRE Mobile ATT&CK techniques from JSON database.")
            return
        except Exception as e:
            logger.warning(f"Failed to load MITRE JSON database: {e}. Falling back to default list.")
    
    # Fallback default list
    TECHNIQUES.update({
        "T1417": {"name": "Input Capture", "tactic": "Collection"},
        "T1636": {"name": "Protected User Data", "tactic": "Collection"},
        "T1636.001": {"name": "SMS Messages", "tactic": "Collection"},
        "T1411": {"name": "Input Prompt", "tactic": "Credential Access"},
        "T1629": {"name": "Impair Defenses", "tactic": "Defense Evasion"},
        "T1629.001": {"name": "Prevent User Interaction", "tactic": "Defense Evasion"},
        "T1406": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
        "T1633": {"name": "Virtualization Solution Discovery", "tactic": "Discovery"},
        "T1430": {"name": "Location Tracking", "tactic": "Collection"},
        "T1521": {"name": "Encrypted Channel", "tactic": "Command and Control"},
        "T1437": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
        "T1407": {"name": "Download New Code at Runtime", "tactic": "Defense Evasion"},
        "T1627": {"name": "Execution Guardrails", "tactic": "Execution"},
    })

load_mitre_techniques()

PERM_TECHNIQUES = {
    "android.permission.RECEIVE_SMS": ["T1636.001"],
    "android.permission.READ_SMS": ["T1636.001"],
    "android.permission.SEND_SMS": ["T1636.001"],
    "android.permission.SYSTEM_ALERT_WINDOW": ["T1411", "T1629.001"],
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ["T1417", "T1411"],
    "android.permission.READ_CONTACTS": ["T1636"],
    "android.permission.ACCESS_FINE_LOCATION": ["T1430"],
}

CODE_PATTERNS = [
    ("DexClassLoader", ["T1407"]),
    ("Runtime.getRuntime().exec", ["T1627"]),
    ("checkServerTrusted", ["T1521"]),
    ("http://", ["T1437"]),
    ("AccessibilityService", ["T1417"]),
    ("ClipboardManager", ["T1417"]),
]


def map_evidence_to_attack(evidence: Dict[str, Any], banking_badges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    hits: Dict[str, Dict[str, Any]] = {}

    def add(tid: str, source: str, detail: str) -> None:
        if tid not in TECHNIQUES:
            return
        if tid not in hits:
            hits[tid] = {
                "id": tid,
                "name": TECHNIQUES[tid]["name"],
                "tactic": TECHNIQUES[tid]["tactic"],
                "sources": [],
            }
        hits[tid]["sources"].append({"source": source, "detail": detail[:120]})

    for perm in evidence.get("permissions") or []:
        name = perm.get("name") or perm.get("permission") or ""
        for tid in PERM_TECHNIQUES.get(name, []):
            add(tid, "permission", name)

    for cat in ("reflection_dynamic_loading", "crypto_issues", "network_indicators", "obfuscation_signals"):
        for item in evidence.get(cat) or []:
            blob = f"{item.get('type', '')} {item.get('description', '')}"
            for pattern, tids in CODE_PATTERNS:
                if pattern.lower() in blob.lower():
                    for tid in tids:
                        add(tid, cat, blob)

    for hit in evidence.get("malware_rule_hits") or []:
        desc = hit.get("description") or hit.get("match") or "Anti-analysis"
        add("T1633", "malware_rule_hits", desc)
        add("T1406", "malware_rule_hits", desc)

    for badge in banking_badges:
        bid = badge.get("id", "")
        if "SMS" in bid:
            add("T1636.001", "banking_fraud", badge.get("title", ""))
        if "OVERLAY" in bid:
            add("T1411", "banking_fraud", badge.get("title", ""))
        if "A11Y" in bid:
            add("T1417", "banking_fraud", badge.get("title", ""))
        if "EXFIL" in bid:
            add("T1437", "banking_fraud", badge.get("title", ""))

    return sorted(hits.values(), key=lambda x: x["id"])
