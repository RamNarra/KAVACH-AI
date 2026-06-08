"""
Banking fraud indicator engine for Kavach AI.
Detects mobile banking trojan patterns from manifest, static code, and runtime events.
"""

import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List
from runtime_findings import RF_ID_SMS_INTERCEPTION, RF_ID_OVERLAY_DRAWING

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

SMS_PERMS = {
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_MMS",
}

OVERLAY_PERMS = {"android.permission.SYSTEM_ALERT_WINDOW"}
A11Y_PERMS = {"android.permission.BIND_ACCESSIBILITY_SERVICE"}

UPI_SCHEMES = re.compile(r"upi://|phonepe://|paytmmp://|gpay://|bhim://|tez://|imobile://|yonosbi://|yono://|hdfcbank://|hdfc://|axispay://|axis://|kotakbank://|kotak://|indmobile://", re.I)
BANK_KEYWORDS = re.compile(
    r"\b(bank|upi|wallet|otp|pin|credential|login|account|transfer|ifsc|card|rupee|lakh|crore|neft|rtgs|nach|aadhaar|pan|cibil|sbi|boi|hdfc|icici|kotak|axis|paytm|phonepe)\b",
    re.I,
)

KNOWN_INDIAN_TROJAN_FAMILIES = {
    "SOVA": {
        "signatures": ["sova", "sovacorp", "accessibility_stealer"],
        "targets": ["SBI YONO", "HDFC Bank", "ICICI iMobile", "Kotak 811"],
        "technique": "Overlay + Cookie Theft + Clipboard Monitor",
        "active_since": "2021",
        "indian_incident_count": 312,
    },
    "BRATA": {
        "signatures": ["brata", "remote_wipe", "factory_reset"],
        "targets": ["Paytm", "PhonePe", "Google Pay"],
        "technique": "Remote Wipe After Transfer",
        "active_since": "2022",
        "indian_incident_count": 87,
    },
    "Xenomorph": {
        "signatures": ["xenomorph", "hadopro", "accessibility_watcher"],
        "targets": ["SBI YONO", "HDFC Bank", "ICICI iMobile"],
        "technique": "Accessibility hijacking + overlay injection",
        "active_since": "2021",
        "indian_incident_count": 140,
    },
    "Cerberus_India": {
        "signatures": ["cerberus", "grub", "pingback_url"],
        "targets": ["Paytm", "SBI YONO", "HDFC Bank"],
        "technique": "SMS Interception + Keylogging",
        "active_since": "2020",
        "indian_incident_count": 450,
    },
    "Drinik": {
        "signatures": ["drinik", "income_tax", "itr"],
        "targets": ["Indian Income Tax portal clones"],
        "technique": "Phishing + Accessibility Screen Reader",
        "active_since": "2021",
        "indian_incident_count": 1200,
    },
}


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
    package_name: str = "",
    filename: str = "",
) -> Dict[str, Any]:
    badges: List[Dict[str, Any]] = []
    runtime_events = runtime_events or []
    runtime_findings = runtime_findings or []
    combined_code = "\n".join(jadx_sources.values()) if jadx_sources else ""
    
    # Strip comments to prevent false positives from code commentary
    def _strip_comments(code: str) -> str:
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        code = re.sub(r'//[^\n]*', '', code)
        return code
    clean_code = _strip_comments(combined_code)

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

    # Extract UPI indications
    upi_in_manifest = [s for s in intent_schemes if UPI_SCHEMES.search(s + "://")]
    upi_in_code = UPI_SCHEMES.findall(clean_code)

    # Compute BFL early to use as confidence check for family attribution
    bfl_score = 1.0
    if permissions & OVERLAY_PERMS or "TYPE_APPLICATION_OVERLAY" in clean_code:
        bfl_score += 2.5
    if permissions & SMS_PERMS:
        bfl_score += 2.5
    if permissions & A11Y_PERMS or "AccessibilityService" in clean_code:
        bfl_score += 3.0
    if upi_in_manifest or upi_in_code:
        bfl_score += 1.5
    if re.search(r"ClipboardManager|getPrimaryClip|InputMethod", clean_code):
        bfl_score += 1.5
    BFL = min(10.0, bfl_score)

    # Check known Indian banking trojans (only if BFL >= 5.0 to avoid false positives on standard apps)
    matched_trojan = None
    matched_trojan_details = {}
    clean_manifest = re.sub(r'<!--.*?-->', '', manifest_content or '', flags=re.DOTALL)
    search_space = f"{package_name} {filename} {clean_manifest} {clean_code}".lower()
    
    if BFL >= 5.0:
        for trojan_name, info in KNOWN_INDIAN_TROJAN_FAMILIES.items():
            for sig in info["signatures"]:
                pattern = rf"(?:\b|\.){re.escape(sig.lower())}(?:\b|\.)"
                if re.search(pattern, search_space):
                    matched_trojan = trojan_name
                    matched_trojan_details = info
                    break
            if matched_trojan:
                break

    if matched_trojan:
        badges.append(
            _badge(
                "BANK-TROJAN-FINGERPRINT",
                f"Indian Banking Trojan Family matched: {matched_trojan}",
                "CRITICAL",
                f"This APK exhibits behavior consistent with the {matched_trojan} trojan family, which has targeted customers of {', '.join(matched_trojan_details['targets'])} across {matched_trojan_details['indian_incident_count']} documented incidents in India.",
                [f"Signature '{sig}' matched. Active since {matched_trojan_details['active_since']}. Technique: {matched_trojan_details['technique']}" for sig in matched_trojan_details["signatures"] if re.search(rf"(?:\b|\.){re.escape(sig.lower())}(?:\b|\.)", search_space)]
            )
        )

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
    if re.search(r"ClipboardManager|getPrimaryClip|InputMethod", clean_code):
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
        category = str(ev.get("category") or "").lower()
        evidence = str(ev.get("evidence") or ev.get("action") or "")
        args = ev.get("args") or {}
        # Ensure we check both the transmission destination (network request/URL) AND the sensitive payload data,
        # rather than triggering simply because an HTTP(S) URL contains a banking keyword or is contacted.
        is_net = "network" in category or "http" in category or re.search(r"https?://", evidence, re.I)
        has_sensitive_data = False
        
        # Check if any sensitive keys or arguments contain banking keywords
        for k, v in args.items():
            if BANK_KEYWORDS.search(str(k)) or BANK_KEYWORDS.search(str(v)):
                has_sensitive_data = True
                break
        if not has_sensitive_data and BANK_KEYWORDS.search(evidence):
            # If the keyword is in the URL itself (like "https://bankofindia.com/api"), we ignore it to prevent false positives.
            # But if it's in a request body or headers (evidence text excluding standard hostnames), we flag it.
            host_match = re.search(r"https?://([^/]+)", evidence, re.I)
            if host_match:
                hostname = host_match.group(1)
                remainder = evidence.replace(hostname, "")
                if BANK_KEYWORDS.search(remainder):
                    has_sensitive_data = True
            else:
                has_sensitive_data = True

        if is_net and has_sensitive_data:
            badges.append(
                _badge(
                    "BANK-CRED-EXFIL",
                    "Cleartext credential traffic",
                    "CRITICAL",
                    "Runtime observed potential sensitive banking-related data transmitted to network endpoints.",
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
        
    # Check for dynamic amplification bonus (multiplicative/additive confirmation effect)
    has_static_overlay = any(b["id"] == "BANK-OVERLAY" for b in badges)
    has_dynamic_overlay = any(b["id"] == f"BANK-RUNTIME-{RF_ID_OVERLAY_DRAWING}" for b in badges)
    
    has_static_sms = any(b["id"] == "BANK-SMS-STEALER" for b in badges)
    has_dynamic_sms = any(b["id"] == f"BANK-RUNTIME-{RF_ID_SMS_INTERCEPTION}" for b in badges)
    
    confirmation_bonus = 0.0
    if has_static_overlay and has_dynamic_overlay:
        confirmation_bonus += 2.0  # Dynamic confirmation of overlay risk
    if has_static_sms and has_dynamic_sms:
        confirmation_bonus += 2.0  # Dynamic confirmation of SMS interception
        
    BFI = min(10.0, bfi_score + confirmation_bonus)
    
    # Calculate composite Banking Fraud Score using average model rather than high-scaling multiplication
    fraud_score = max(0, min(100, int(((BFL + BFI) / 2.0) * 10.0)))
    if not badges:
        fraud_score = 0

    if matched_trojan:
        fraud_score = max(fraud_score, 98)

    actions: List[str] = []
    if any(b["id"] == "BANK-OVERLAY" for b in badges):
        actions.append("Block app installation org-wide; warn customers about overlay phishing.")
    if any(b["id"] == "BANK-SMS-STEALER" for b in badges):
        actions.append("Monitor SMS OTP channel; consider step-up auth for affected users.")
    if fraud_score >= 60 or exfil_observed:
        actions.append("Escalate to fraud desk — high-confidence mobile banking trojan indicators.")
    if matched_trojan:
        actions.append(f"Deploy emergency mitigation and signatures for the {matched_trojan} trojan family.")

    return {
        "fraud_score": fraud_score,
        "badges": badges,
        "recommended_actions": actions,
        "indicator_count": len(badges),
        "matched_trojan": matched_trojan,
    }
