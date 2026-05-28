import json
import re
import xml.etree.ElementTree as ET
from typing import Dict, Any, List

DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS": 20,
    "android.permission.READ_SMS": 20,
    "android.permission.RECEIVE_SMS": 20,
    "android.permission.READ_CONTACTS": 15,
    "android.permission.WRITE_CONTACTS": 15,
    "android.permission.ACCESS_FINE_LOCATION": 10,
    "android.permission.ACCESS_COARSE_LOCATION": 10,
    "android.permission.RECORD_AUDIO": 15,
    "android.permission.CAMERA": 15,
    "android.permission.READ_PHONE_STATE": 10,
    "android.permission.SYSTEM_ALERT_WINDOW": 25,
    "android.permission.BIND_DEVICE_ADMIN": 25,
    "android.permission.REQUEST_INSTALL_PACKAGES": 15,
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 25,
}

# Regex definitions for URLs and secrets
URL_REGEX = re.compile(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s"\']*)?')
SECRET_REGEX = re.compile(r'(?:api_key|apikey|secret|password|private_key|token|auth_token|jwt_token)\s*=\s*[\'"]([a-zA-Z0-9+/=_\-\.@]{16,})[\'"]', re.IGNORECASE)

DANGEROUS_CODE_PATTERNS = [
    ("http://", 5, "Cleartext HTTP traffic", "network_indicators"),
    ("Runtime.getRuntime().exec", 20, "Command execution via Runtime.exec", "reflection_dynamic_loading"),
    ("DexClassLoader", 20, "Dynamic code loading via DexClassLoader", "reflection_dynamic_loading"),
    ("ProcessBuilder", 15, "Command execution via ProcessBuilder", "reflection_dynamic_loading"),
    ("Cipher.getInstance(\"AES/ECB", 10, "Insecure AES ECB encryption", "crypto_issues"),
    ("Cipher.getInstance(\'AES/ECB", 10, "Insecure AES ECB encryption", "crypto_issues"),
    ("checkServerTrusted", 15, "Insecure TrustManager (TrustAll)", "crypto_issues"),
    ("MODE_WORLD_READABLE", 10, "World-readable SharedPreferences", "data_storage_issues"),
    ("System.loadLibrary", 5, "Loading native libraries", "obfuscation_signals"),
    ("Base64.decode", 2, "Base64 decoding (possible obfuscation)", "obfuscation_signals"),
]

def analyze_manifest(manifest_content: str) -> Dict[str, Any]:
    findings = {
        "permissions": [],
        "exported_components": [],
        "dangerous_manifest_flags": [],
        "score": 0
    }
    if not manifest_content:
        return findings

    try:
        root = ET.fromstring(manifest_content)
        # Check permissions
        for perm in root.findall(".//uses-permission"):
            name = perm.attrib.get("{http://schemas.android.com/apk/res/android}name")
            if name:
                if name in DANGEROUS_PERMISSIONS:
                    sc = DANGEROUS_PERMISSIONS[name]
                    findings["score"] += sc
                    findings["permissions"].append({
                        "name": name,
                        "risk_score": sc,
                        "description": f"Dangerous permission: {name.split('.')[-1]}"
                    })

        # Check exported components
        for tag in ["activity", "service", "receiver", "provider"]:
            for comp in root.findall(f".//{tag}"):
                exported = comp.attrib.get("{http://schemas.android.com/apk/res/android}exported")
                name = comp.attrib.get("{http://schemas.android.com/apk/res/android}name", "Unknown")
                if exported == "true":
                    findings["score"] += 5
                    findings["exported_components"].append({
                        "name": name,
                        "type": tag,
                        "risk_score": 5,
                        "description": f"Exported {tag} is publicly accessible"
                    })

        # Cleartext traffic
        app = root.find(".//application")
        if app is not None:
            cleartext = app.attrib.get("{http://schemas.android.com/apk/res/android}usesCleartextTraffic")
            if cleartext == "true":
                findings["score"] += 15
                findings["dangerous_manifest_flags"].append({
                    "flag": "usesCleartextTraffic=true",
                    "risk_score": 15,
                    "description": "Cleartext HTTP traffic permitted globally"
                })

    except Exception as e:
        findings["dangerous_manifest_flags"].append({
            "flag": "manifest_error",
            "risk_score": 0,
            "description": f"Manifest parsing error: {e}"
        })

    return findings

def analyze_jadx(jadx_sources: Dict[str, str]) -> Dict[str, Any]:
    findings = {
        "network_indicators": [],
        "data_storage_issues": [],
        "crypto_issues": [],
        "hardcoded_secrets": [],
        "suspicious_urls": [],
        "reflection_dynamic_loading": [],
        "obfuscation_signals": [],
        "score": 0
    }
    
    matched_patterns = set()

    for path, code in jadx_sources.items():
        # Match code patterns
        for pattern_str, sc, desc, category in DANGEROUS_CODE_PATTERNS:
            if pattern_str in code:
                pattern_key = f"{path}:{desc}"
                if pattern_key not in matched_patterns:
                    matched_patterns.add(pattern_key)
                    findings["score"] += sc
                    findings[category].append({
                        "type": desc,
                        "file": path,
                        "risk_score": sc,
                        "description": f"Found {desc} inside source file."
                    })
        
        # Extract URLs
        urls = URL_REGEX.findall(code)
        for url in urls:
            # Filter out common benign schema URLs
            if any(x in url for x in ["schemas.android.com", "google.com/apk", "w3.org", "android.com/tools"]):
                continue
            findings["suspicious_urls"].append({
                "url": url,
                "file": path
            })
            
        # Extract secrets
        secrets = SECRET_REGEX.findall(code)
        for sec in secrets:
            # Avoid matching standard variable types or short words
            if len(sec) < 16:
                continue
            findings["score"] += 10
            findings["hardcoded_secrets"].append({
                "type": "Possible Hardcoded Secret/Key",
                "file": path,
                "risk_score": 10,
                "description": f"Found suspicious string token containing potential secret key."
            })

    return findings

def analyze_quark(quark_json_path: str) -> Dict[str, Any]:
    findings = {
        "malware_rule_hits": [],
        "score": 0
    }
    try:
        with open(quark_json_path, "r") as f:
            data = json.load(f)
            crimes = data.get("crimes", [])
            for crime in crimes:
                confidence = crime.get("confidence", "0%")
                rule = crime.get("rule", "Unknown rule")
                if isinstance(confidence, str) and confidence.endswith("%"):
                    conf_val = int(confidence[:-1])
                else:
                    conf_val = int(confidence)
                
                # Weight by confidence (100% -> 10 pts)
                add_score = int(conf_val / 10)
                findings["score"] += add_score
                findings["malware_rule_hits"].append({
                    "rule": rule,
                    "confidence": confidence,
                    "risk_score": add_score,
                    "description": f"Quark rule hit: {rule} ({confidence})"
                })
    except Exception:
        pass
    
    return findings

def calculate_deterministic_score(manifest_content: str, jadx_sources: Dict[str, str], quark_json_path: str) -> Dict[str, Any]:
    m_res = analyze_manifest(manifest_content)
    j_res = analyze_jadx(jadx_sources)
    q_res = analyze_quark(quark_json_path)

    total_score = m_res["score"] + j_res["score"] + q_res["score"]
    clamped_score = max(0, min(100, total_score))

    threat_level = "SAFE"
    if clamped_score >= 85:
        threat_level = "CRITICAL"
    elif clamped_score >= 65:
        threat_level = "HIGH"
    elif clamped_score >= 40:
        threat_level = "MEDIUM"
    elif clamped_score >= 15:
        threat_level = "LOW"

    # Assemble normalized evidence model
    evidence = {
        "permissions": m_res["permissions"],
        "exported_components": m_res["exported_components"],
        "dangerous_manifest_flags": m_res["dangerous_manifest_flags"],
        "network_indicators": j_res["network_indicators"],
        "data_storage_issues": j_res["data_storage_issues"],
        "crypto_issues": j_res["crypto_issues"],
        "hardcoded_secrets": j_res["hardcoded_secrets"],
        "suspicious_urls": j_res["suspicious_urls"],
        "reflection_dynamic_loading": j_res["reflection_dynamic_loading"],
        "obfuscation_signals": j_res["obfuscation_signals"],
        "malware_rule_hits": q_res["malware_rule_hits"]
    }

    # Format description summaries for Vertex AI prompt context
    manifest_details = [f"- {p['description']}" for p in evidence["permissions"]]
    manifest_details += [f"- {ec['description']}: {ec['name']}" for ec in evidence["exported_components"]]
    manifest_details += [f"- {f['description']}" for f in evidence["dangerous_manifest_flags"]]
    
    jadx_details = []
    for cat in ["network_indicators", "data_storage_issues", "crypto_issues", "hardcoded_secrets", "reflection_dynamic_loading", "obfuscation_signals"]:
        for item in evidence[cat]:
            jadx_details.append(f"- {item['type']} found in {item['file']}")
            
    quark_details = [f"- {hit['description']}" for hit in evidence["malware_rule_hits"]]

    return {
        "risk_score": clamped_score,
        "threat_level": threat_level,
        "raw_score": total_score,
        "evidence": evidence,
        "details": {
            "manifest": manifest_details,
            "jadx": jadx_details,
            "quark": quark_details
        }
    }
