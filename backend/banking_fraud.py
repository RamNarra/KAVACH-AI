"""
Banking fraud indicator engine for Kavach AI.
Detects mobile banking trojan patterns from manifest, static code, and runtime events.
"""

import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

SMS_PERMS = {
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_MMS",
}

OVERLAY_PERMS = {"android.permission.SYSTEM_ALERT_WINDOW"}
A11Y_PERMS = {"android.permission.BIND_ACCESSIBILITY_SERVICE"}

UPI_SCHEMES = re.compile(r"upi://|phonepe://|paytmmp://|gpay://|bhim://", re.I)
BANK_KEYWORDS = re.compile(
    r"\b(bank|upi|wallet|otp|pin|credential|login|account|transfer|ifsc|card)\b",
    re.I,
)


def _badge(badge_id: str, title: str, severity: str, summary: str, evidence: List[str]) -> Dict[str, Any]:
    return {
        "id": badge_id,
        "title": title,
        "severity": severity,
        "summary": summary,
        "evidence": evidence[:5],
    }


def analyze_banking_fraud(
    manifest_content: str,
    jadx_sources: Dict[str, str],
    runtime_events: List[Dict[str, Any]] | None = None,
    runtime_findings: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    badges: List[Dict[str, Any]] = []
    runtime_events = runtime_events or []
    runtime_findings = runtime_findings or []
    combined_code = "\n".join(jadx_sources.values()) if jadx_sources else ""

    permissions: set[str] = set()
    intent_schemes: List[str] = []
    exported_activities: List[str] = []

    if manifest_content:
        try:
            root = ET.fromstring(manifest_content)
            for perm in root.findall(".//uses-permission"):
                name = perm.attrib.get(f"{ANDROID_NS}name")
                if name:
                    permissions.add(name)
            for activity in root.findall(".//activity"):
                name = activity.attrib.get(f"{ANDROID_NS}name", "")
                if activity.attrib.get(f"{ANDROID_NS}exported") == "true":
                    exported_activities.append(name)
                for intent in activity.findall(".//data"):
                    scheme = intent.attrib.get(f"{ANDROID_NS}scheme")
                    if scheme:
                        intent_schemes.append(scheme)
        except ET.ParseError:
            pass

    # SMS stealer
    sms_hits = permissions & SMS_PERMS
    if sms_hits:
        badges.append(
            _badge(
                "BANK-SMS-STEALER",
                "SMS interception capability",
                "HIGH",
                "App requests SMS permissions commonly abused to intercept OTP and banking messages.",
                [f"Permission: {p}" for p in sorted(sms_hits)],
            )
        )

    # Overlay attack
    if permissions & OVERLAY_PERMS or "TYPE_APPLICATION_OVERLAY" in combined_code:
        badges.append(
            _badge(
                "BANK-OVERLAY",
                "Overlay / screen capture risk",
                "HIGH",
                "Can draw over other apps — classic banking trojan technique for credential theft.",
                ["SYSTEM_ALERT_WINDOW"] if "android.permission.SYSTEM_ALERT_WINDOW" in permissions else ["TYPE_APPLICATION_OVERLAY in code"],
            )
        )

    # Accessibility hijack
    if permissions & A11Y_PERMS or "AccessibilityService" in combined_code:
        badges.append(
            _badge(
                "BANK-A11Y-HIJACK",
                "Accessibility service abuse",
                "CRITICAL",
                "Accessibility APIs can automate taps and read on-screen banking credentials.",
                ["BIND_ACCESSIBILITY_SERVICE"] if A11Y_PERMS & permissions else ["AccessibilityService referenced"],
            )
        )

    # UPI / payment targeting
    upi_in_manifest = [s for s in intent_schemes if UPI_SCHEMES.search(s + "://")]
    upi_in_code = UPI_SCHEMES.findall(combined_code)
    if upi_in_manifest or upi_in_code:
        badges.append(
            _badge(
                "BANK-UPI-TARGET",
                "Payment scheme targeting",
                "MEDIUM",
                "Registers or references UPI/payment deep links — may target wallet flows.",
                (upi_in_manifest + list(set(upi_in_code)))[:5],
            )
        )

    # Keylogging / clipboard
    if re.search(r"ClipboardManager|getPrimaryClip|InputMethod", combined_code):
        badges.append(
            _badge(
                "BANK-KEYLOG",
                "Input or clipboard monitoring",
                "HIGH",
                "Code references clipboard or input capture — sensitive for banking credentials.",
                ["ClipboardManager or InputMethod usage detected"],
            )
        )

    # Credential exfil at runtime
    for ev in runtime_events:
        evidence = str(ev.get("evidence") or ev.get("action") or "")
        if BANK_KEYWORDS.search(evidence) and re.search(r"http://", evidence, re.I):
            badges.append(
                _badge(
                    "BANK-CRED-EXFIL",
                    "Cleartext credential traffic",
                    "CRITICAL",
                    "Runtime observed potential banking-related data over unencrypted HTTP.",
                    [evidence[:200]],
                )
            )
            break

    for rf in runtime_findings:
        title = (rf.get("title") or "").lower()
        if any(k in title for k in ("clipboard", "sms", "http", "credential", "overlay")):
            badges.append(
                _badge(
                    f"BANK-RUNTIME-{rf.get('id', 'finding')[:12]}",
                    rf.get("title", "Runtime banking signal"),
                    rf.get("severity", "MEDIUM"),
                    rf.get("summary", "Runtime finding with banking relevance."),
                    (rf.get("evidence_items") or [])[:3],
                )
            )

    # Overhaul banking fraud scoring using the transparent Likelihood x Impact matrix model
    # 1. Banking Fraud Likelihood (BFL, 1.0 to 10.0)
    # Measures the static capability set of a banking trojan
    bfl_score = 1.0
    
    if permissions & OVERLAY_PERMS or "TYPE_APPLICATION_OVERLAY" in combined_code:
        bfl_score += 2.5
    if permissions & SMS_PERMS:
        bfl_score += 2.5
    if permissions & A11Y_PERMS or "AccessibilityService" in combined_code:
        bfl_score += 3.0
    if upi_in_manifest or upi_in_code:
        bfl_score += 1.5
    if re.search(r"ClipboardManager|getPrimaryClip|InputMethod", combined_code):
        bfl_score += 1.5
        
    BFL = min(10.0, bfl_score)

    # 2. Banking Fraud Technical Impact (BFI, 1.0 to 10.0)
    # Measures active live observations, data exfiltration, or confirmed accessibility hijack
    bfi_score = 1.0
    exfil_observed = False
    
    for b in badges:
        if b["id"] == "BANK-CRED-EXFIL":
            bfi_score += 5.0
            exfil_observed = True
        elif b["id"] == "BANK-A11Y-HIJACK":
            bfi_score += 3.5
        elif b["id"] == "BANK-OVERLAY":
            bfi_score += 2.5
            
        weight = {"CRITICAL": 3.0, "HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.5}.get(b["severity"], 1.0)
        bfi_score += weight * 0.5
        
    BFI = min(10.0, bfi_score)
    
    # Calculate composite Banking Fraud Score using average model rather than high-scaling multiplication
    fraud_score = max(0, min(100, int(((BFL + BFI) / 2.0) * 10.0)))
    if not badges:
        fraud_score = 0

    actions: List[str] = []
    if any(b["id"] == "BANK-OVERLAY" for b in badges):
        actions.append("Block app installation org-wide; warn customers about overlay phishing.")
    if any(b["id"] == "BANK-SMS-STEALER" for b in badges):
        actions.append("Monitor SMS OTP channel; consider step-up auth for affected users.")
    if fraud_score >= 60 or exfil_observed:
        actions.append("Escalate to fraud desk — high-confidence mobile banking trojan indicators.")

    return {
        "fraud_score": fraud_score,
        "badges": badges,
        "recommended_actions": actions,
        "indicator_count": len(badges),
    }
