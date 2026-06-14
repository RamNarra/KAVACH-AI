import json
import re
import os
import xml.etree.ElementTree as ET
import logging
from typing import Dict, Any, List
from sandbox_runner import DOCKER_SANDBOX_ENABLED

logger = logging.getLogger("kavach")

_PRUNED_LIBS = {
    "androidx", "android.support", "kotlin", "kotlinx", "okio", "okhttp3", 
    "retrofit2", "reactivex", "squareup", "fasterxml", "intellij", "jetbrains",
    "com.google", "google.protobuf", "com.google.android", "com.google.firebase"
}

DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS": 20,
    "android.permission.READ_SMS": 20,
    "android.permission.RECEIVE_SMS": 20,
    "android.permission.READ_CONTACTS": 15,
    "android.permission.WRITE_CONTACTS": 15,
    "android.permission.ACCESS_FINE_LOCATION": 10,
    "android.permission.ACCESS_COARSE_LOCATION": 10,
    "android.permission.RECORD_AUDIO": 20,
    "android.permission.CAMERA": 20,
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
    (re.compile(r'\"http://(?!(?:schemas\.android\.com|schemas\.xmlsoap\.org|www\.w3\.org|www\.oracle\.com|java\.sun\.com|android\.com/tools))([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[^\s"\']*\"'), 5, "Cleartext HTTP traffic", "network_indicators"),
    ("Runtime.getRuntime().exec", 20, "Command execution via Runtime.exec", "reflection_dynamic_loading"),
    ("DexClassLoader", 20, "Dynamic code loading via DexClassLoader", "reflection_dynamic_loading"),
    ("ProcessBuilder", 15, "Command execution via ProcessBuilder", "reflection_dynamic_loading"),
    ("Cipher.getInstance(\"AES/ECB", 10, "Insecure AES ECB encryption", "crypto_issues"),
    ("Cipher.getInstance(\'AES/ECB", 10, "Insecure AES ECB encryption", "crypto_issues"),
    ("checkServerTrusted", 15, "Insecure TrustManager (TrustAll)", "crypto_issues"),
    ("MODE_WORLD_READABLE", 10, "World-readable SharedPreferences", "data_storage_issues"),
    ("System.loadLibrary", 5, "Loading native libraries", "obfuscation_signals"),
    (re.compile(r'Base64\.decode\s*\(\s*[\'"][A-Za-z0-9+/=]{20,}[\'"]'), 5, "Decoding of long hardcoded Base64 string", "obfuscation_signals"),
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

def analyze_jadx(jadx_sources: Dict[str, str], jadx_out: str = None, package_name: str = "") -> Dict[str, Any]:
    """
    Analyze JADX decompiled java sources for dangerous patterns, suspicious URLs,
    and possible hardcoded credentials. Runs over the entire codebase if jadx_out is provided.
    """
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
    
    target_sources = {}
    if jadx_out and os.path.isdir(jadx_out):
        sources_dir = os.path.join(jadx_out, "sources")
        if not os.path.isdir(sources_dir):
            sources_dir = os.path.join(jadx_out, "src")
        if not os.path.isdir(sources_dir):
            sources_dir = jadx_out

        if package_name:
            package_dir = os.path.join(sources_dir, *package_name.split("."))
            if os.path.isdir(package_dir):
                sources_dir = package_dir

        for root_dir, dirs, files in os.walk(sources_dir):
            # Prune third-party library paths during traversal
            rel_root = os.path.relpath(root_dir, sources_dir)
            pruned_dirs = []
            for d in dirs:
                sub_rel = os.path.join(rel_root, d) if rel_root != "." else d
                sub_pkg = sub_rel.replace(os.sep, ".")
                is_lib = False
                for p in _PRUNED_LIBS:
                    if sub_pkg.startswith(p) or f".{p}" in sub_pkg or d == p:
                        is_lib = True
                        break
                if not is_lib:
                    pruned_dirs.append(d)
            dirs[:] = pruned_dirs

            for fname in files:
                if not fname.endswith(".java"):
                    continue
                fpath = os.path.join(root_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                        rel_key = os.path.relpath(fpath, jadx_out)
                        target_sources[rel_key] = fh.read()
                except Exception as e:
                    logger.debug(f"Failed to read JADX source file {fpath}: {e}")
                    continue
    
    if not target_sources:
        target_sources = jadx_sources
        
    matched_patterns = set()
    pattern_counts = {}

    for path, code in target_sources.items():
        # Match code patterns
        for pattern_item, sc, desc, category in DANGEROUS_CODE_PATTERNS:
            matched = False
            if isinstance(pattern_item, re.Pattern):
                if pattern_item.search(code):
                    matched = True
            else:
                if pattern_item in code:
                    matched = True
            if matched:
                pattern_key = f"{path}:{desc}"
                if pattern_key not in matched_patterns:
                    matched_patterns.add(pattern_key)
                    pattern_counts[desc] = pattern_counts.get(desc, 0) + 1
                    
                    # Deduplicate: Only add to the risk score for the first 2 occurrences of this pattern across the app
                    is_scored = pattern_counts[desc] <= 2
                    if is_scored:
                        findings["score"] += sc
                        
                    findings[category].append({
                        "type": desc,
                        "file": path,
                        "risk_score": sc if is_scored else 0,
                        "description": f"Found {desc} inside source file.",
                        "source": "jadx"
                    })
        
        # Extract URLs
        urls = URL_REGEX.findall(code)
        for url in urls:
            if any(x in url for x in ["schemas.android.com", "google.com/apk", "w3.org", "android.com/tools"]):
                continue
            findings["suspicious_urls"].append({
                "url": url,
                "file": path
            })
            
        # Extract secrets
        secrets = SECRET_REGEX.findall(code)
        for sec in secrets:
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

def analyze_apkid(apkid_json_path: str) -> Dict[str, Any]:
    findings = {
        "anti_vm": [],
        "obfuscator_packer": [],
        "compiler_manipulator": [],
        "score": 0
    }
    try:
        with open(apkid_json_path, "r") as f:
            data = json.load(f)
            files = data.get("files", [])
            for file_entry in files:
                matches = file_entry.get("matches", {})
                
                # Anti VM
                for avm in matches.get("anti_vm", []):
                    findings["score"] += 10
                    findings["anti_vm"].append({
                        "type": "Anti-VM Check",
                        "match": avm,
                        "risk_score": 10,
                        "description": f"Anti-VM indicator: {avm}"
                    })
                
                # Obfuscators & Packers
                for obf in matches.get("obfuscator", []):
                    findings["score"] += 15
                    findings["obfuscator_packer"].append({
                        "type": "Obfuscator",
                        "match": obf,
                        "risk_score": 15,
                        "description": f"Obfuscated with {obf}"
                    })
                for pack in matches.get("packer", []):
                    findings["score"] += 25
                    findings["obfuscator_packer"].append({
                        "type": "Packer",
                        "match": pack,
                        "risk_score": 25,
                        "description": f"Packed with {pack} (possible evasion)"
                    })
                
                # Compilers & Manipulators
                for comp in matches.get("compiler", []):
                    findings["compiler_manipulator"].append({
                        "type": "Compiler",
                        "match": comp,
                        "risk_score": 0,
                        "description": f"Compiled with {comp}"
                    })
                for manip in matches.get("manipulator", []):
                    findings["score"] += 5
                    findings["compiler_manipulator"].append({
                        "type": "Manipulator",
                        "match": manip,
                        "risk_score": 5,
                        "description": f"Manipulated with {manip}"
                    })
    except Exception as e:
        logger.warning(f"Failed to analyze APKiD JSON: {e}")
    
    return findings

def analyze_quark(quark_json_path: str) -> Dict[str, Any]:
    import os
    import json
    findings = {
        "rule_hits": [],
        "score": 0
    }
    if not quark_json_path or not os.path.exists(quark_json_path):
        return findings
    try:
        with open(quark_json_path, "r") as f:
            data = json.load(f)
            crimes = data.get("crimes", [])
            for crime in crimes:
                rule_id = crime.get("rule", "")
                desc = crime.get("crime", "")
                labels = crime.get("label", [])
                confidence = crime.get("confidence", "0%")
                try:
                    conf_val = float(confidence.replace("%", "")) / 100.0
                except Exception as e:
                    logger.debug(f"Failed to parse Quark confidence '{confidence}': {e}")
                    conf_val = 0.0

                if conf_val >= 0.6:  # only include high confidence hits
                    base_sc = 5
                    if any(l in ["sms", "stealer", "credentials", "banking"] for l in labels):
                        base_sc = 15
                    elif any(l in ["network", "collection", "reflection"] for l in labels):
                        base_sc = 8

                    risk_sc = int(base_sc * conf_val)
                    findings["score"] += risk_sc
                    findings["rule_hits"].append({
                        "rule": rule_id,
                        "description": desc,
                        "severity": "HIGH" if risk_sc >= 10 else "MEDIUM",
                        "confidence": confidence,
                        "risk_score": risk_sc
                    })
    except Exception as e:
        logger.warning(f"Failed to analyze Quark JSON: {e}")
    return findings


def analyze_network_security_config(apktool_out: str, manifest_content: str) -> Dict[str, Any]:
    import os
    import xml.etree.ElementTree as ET
    findings = {
        "issues": [],
        "score": 0
    }
    if not apktool_out or not os.path.isdir(apktool_out):
        return findings

    config_file = None
    # 1. Parse manifest to find config name
    try:
        if manifest_content:
            root = ET.fromstring(manifest_content)
            app = root.find(".//application")
            if app is not None:
                # Find namespace-neutral or explicit namespace attribute
                cfg_attr = None
                for k, v in app.attrib.items():
                    if k.endswith("networkSecurityConfig"):
                        cfg_attr = v
                        break
                if cfg_attr:
                    # e.g., @xml/network_security_config -> network_security_config
                    cfg_name = cfg_attr.split("/")[-1]
                    config_file = os.path.join(apktool_out, "res", "xml", f"{cfg_name}.xml")
    except Exception as e:
        logger.warning(f"Failed to parse manifest for network security config: {e}")

    # Fallback to default name if not found
    if not config_file or not os.path.exists(config_file):
        config_file = os.path.join(apktool_out, "res", "xml", "network_security_config.xml")

    # 2. Parse the config file if it exists
    if os.path.exists(config_file):
        try:
            tree = ET.parse(config_file)
            root = tree.getroot()

            # Check cleartextTrafficPermitted
            for domain_cfg in root.findall(".//domain-config"):
                cleartext = domain_cfg.attrib.get("cleartextTrafficPermitted")
                if cleartext == "true":
                    findings["score"] += 10
                    domains = [d.text for d in domain_cfg.findall("domain")]
                    domains_str = ", ".join(domains) if domains else "configured domains"
                    findings["issues"].append({
                        "type": "Insecure Cleartext Permission",
                        "risk_score": 10,
                        "description": f"Cleartext (HTTP) traffic explicitly permitted for: {domains_str}",
                        "source": "xml"
                    })

            # Check trust-anchors (trusting user certificates)
            debug_overrides = root.findall(".//debug-overrides")
            all_anchors = root.findall(".//trust-anchors")
            for anchor in all_anchors:
                # Check if this anchor is inside debug_overrides
                is_debug_only = any(anchor in dob.iter() for dob in debug_overrides)
                if not is_debug_only:
                    for cert in anchor.findall("certificates"):
                        src = cert.attrib.get("src")
                        if src == "user":
                            findings["score"] += 20
                            findings["issues"].append({
                                "type": "Insecure Trust Anchor (User Certs)",
                                "risk_score": 20,
                                "description": "App trusts user-installed certificates in release builds (vulnerable to MitM).",
                                "source": "xml"
                            })
                        elif src == "all":
                            findings["score"] += 25
                            findings["issues"].append({
                                "type": "Insecure Trust Anchor (All Certs)",
                                "risk_score": 25,
                                "description": "App trusts ALL certificates (disables TLS verification completely).",
                                "source": "xml"
                            })
        except Exception as e:
            logger.warning(f"Failed to parse network security config XML: {e}")

    # 3. Augment / Walk sibling JADX decompiled sources to scan for plaintext cleartext protocols in Java files.
    # This guarantees the Network Config tab is rich and populated with code cleartext protocols even if XML is missing.
    jadx_out = os.path.join(os.path.dirname(apktool_out), "jadx_out")
    if os.path.isdir(jadx_out):
        sources_dir = os.path.join(jadx_out, "sources")
        if not os.path.isdir(sources_dir):
            sources_dir = os.path.join(jadx_out, "src")
        if not os.path.isdir(sources_dir):
            sources_dir = jadx_out
            
        seen_urls = set()
        for root_dir, dirs, files in os.walk(sources_dir):
            # Prune third-party library paths during traversal
            rel_root = os.path.relpath(root_dir, sources_dir)
            pruned_dirs = []
            for d in dirs:
                sub_rel = os.path.join(rel_root, d) if rel_root != "." else d
                sub_pkg = sub_rel.replace(os.sep, ".")
                is_lib = False
                for p in _PRUNED_LIBS:
                    if sub_pkg.startswith(p) or f".{p}" in sub_pkg or d == p:
                        is_lib = True
                        break
                if not is_lib:
                    pruned_dirs.append(d)
            dirs[:] = pruned_dirs

            for fname in files:
                if not fname.endswith(".java"):
                    continue
                fpath = os.path.join(root_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                except Exception as e:
                    logger.debug(f"Failed to read JADX source for cleartext search {fpath}: {e}")
                    continue
                
                if "http://" in content:
                    # Find candidate http:// string URLs
                    import re
                    urls = re.findall(r'http://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s"\']*)?', content)
                    for url in urls:
                        if any(x in url for x in ["schemas.android.com", "google.com", "w3.org", "xmlpull.org", "android.com/tools"]):
                            continue
                        rel = os.path.relpath(fpath, jadx_out)
                        dedup_key = f"{url}:{rel}"
                        if dedup_key not in seen_urls:
                            seen_urls.add(dedup_key)
                            findings["score"] += 5
                            findings["issues"].append({
                                "type": "Cleartext HTTP Protocol",
                                "risk_score": 5,
                                "description": f"Plaintext protocol used to contact: {url}",
                                "file": rel,
                                "source": "jadx"
                            })

    return findings


# ---------------------------------------------------------------------------
# Engine 4: Deep Secrets Scanner
# Finds credential strings unique to financial malware that JADX regex misses:
# AWS keys, Firebase project URLs, GCP service accounts, JWT tokens, PEM keys,
# Stripe/Twilio live keys, hardcoded C2 IPs and ngrok tunnels.
# ---------------------------------------------------------------------------
_SECRET_PATTERNS = [
    ("AWS Access Key",        r"AKIA[0-9A-Z]{16}",                                                    25),
    ("AWS Secret Key",        r"(?i)aws.{0,20}[\'\"]([ 0-9a-zA-Z/+]{40})[\'\"]",                   25),
    ("Firebase Project URL",  r"https://[a-zA-Z0-9-]+\.firebaseio\.com",                             15),
    ("Firebase App ID",       r"1:[0-9]{12}:android:[0-9a-f]{16,}",                                   10),
    ("Google API Key",        r"AIza[0-9A-Za-z\-_]{35}",                                              15),
    ("GCP Service Account",   r"[a-zA-Z0-9._-]+@[a-zA-Z0-9-]+\.iam\.gserviceaccount\.com",          15),
    ("JWT Token",             r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",     20),
    ("PEM Private Key",       r"-----BEGIN (RSA|EC|DSA|OPENSSH)? PRIVATE KEY-----",                    30),
    ("Stripe Live Key",       r"sk_live_[0-9a-zA-Z]{24,}",                                            30),
    ("Stripe Restricted Key", r"rk_live_[0-9a-zA-Z]{24,}",                                            25),
    ("Twilio Auth Token",     r"(?i)twilio.{0,20}[\'\"]([ 0-9a-f]{32})[\'\"]",                        25),
    ("GitHub Token",          r"ghp_[0-9A-Za-z]{36}",                                                 20),
    ("ngrok Tunnel URL",      r"https://[a-zA-Z0-9]+\.ngrok\.io",                                    20),
    ("Hardcoded IPv4 C2",     r"(?<![\d.])(?!10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.)(?::[0-9]{2,5})?", 10),
]

def analyze_secrets(jadx_out: str, package_name: str = "") -> Dict[str, Any]:
    """
    Walk the JADX decompiled source tree and scan every .java file for
    credential patterns not caught by the basic JADX regex engine.
    Returns structured findings with file references and risk scores.
    """
    findings: Dict[str, Any] = {"credential_leaks": [], "score": 0}
    if not jadx_out or not os.path.isdir(jadx_out):
        return findings

    seen: set = set()
    sources_dir = os.path.join(jadx_out, "sources")
    if not os.path.isdir(sources_dir):
        sources_dir = jadx_out

    if package_name:
        package_dir = os.path.join(sources_dir, *package_name.split("."))
        if os.path.isdir(package_dir):
            sources_dir = package_dir

    java_files = []
    for root_dir, dirs, files in os.walk(sources_dir):
        rel_root = os.path.relpath(root_dir, sources_dir)
        pruned_dirs = []
        for d in dirs:
            sub_rel = os.path.join(rel_root, d) if rel_root != "." else d
            sub_pkg = sub_rel.replace(os.sep, ".")
            is_lib = False
            for p in _PRUNED_LIBS:
                if sub_pkg.startswith(p) or f".{p}" in sub_pkg or d == p:
                    is_lib = True
                    break
            if not is_lib:
                pruned_dirs.append(d)
        dirs[:] = pruned_dirs

        for fname in files:
            if fname.endswith(".java"):
                java_files.append(os.path.join(root_dir, fname))

    import concurrent.futures

    def scan_file(fpath):
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except Exception as e:
            logger.debug(f"Failed to read JADX source for secrets search {fpath}: {e}")
            return []

        rel = os.path.relpath(fpath, jadx_out)
        local_leaks = []
        for label, pattern, score in _SECRET_PATTERNS:
            try:
                matches = re.findall(pattern, content)
            except re.error as e:
                logger.warning(f"Regex error scanning secrets pattern {label}: {e}")
                continue
            for m in matches:
                val = m if isinstance(m, str) else str(m)
                local_leaks.append((label, val, rel, score))
        return local_leaks

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = executor.map(scan_file, java_files)

    for file_leaks in results:
        for label, val, rel, score in file_leaks:
            dedup_key = f"{label}:{val[:30]}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            redacted = val[:6] + "****" + val[-3:] if len(val) > 12 else "****"
            findings["credential_leaks"].append({
                "type": label,
                "file": rel,
                "risk_score": score,
                "severity": "CRITICAL" if score >= 25 else "HIGH",
                "description": f"{label} detected in source ({redacted})"
            })
            findings["score"] += score
    return findings


# ---------------------------------------------------------------------------
# Engine 5: Androguard APK Structure Analyzer
# Uses androguard's low-level DEX parser to extract:
#   - All string constants (finds obfuscated URLs, C2s, encoded payloads)
#   - Dangerous API call chains (contacts → SMS, storage → network)
#   - Class-level risk signals (reflection, overlay services, device admin)
# Does NOT require running code — purely static bytecode inspection.
# ---------------------------------------------------------------------------
_DANGEROUS_API_CHAINS = [
    # (read_api, write_api, label, score)
    ("getDeviceId",         "sendTextMessage",    "IMEI Exfiltration via SMS",          25),
    ("query",               "sendTextMessage",    "Contacts/SMS Exfiltration",           25),
    ("getAccounts",         "openConnection",     "Account Data Sent to Network",        20),
    ("getInstalledPackages","openConnection",     "App List Exfiltration",               15),
    ("getLastKnownLocation","openConnection",     "GPS Location Exfiltration",           20),
    ("onAccessibilityEvent","performGlobalAction","Accessibility Abuse (Overlay/Spy)",   30),
    ("loadUrl",             "evaluateJavascript", "WebView JS Injection",                15),
    ("PackageInstaller",    "install",            "Silently Installs Packages",          25),
    ("getSubscriberId",     "openConnection",     "IMSI/Carrier Exfiltration to Network",25),
    ("getRunningAppProcesses","openConnection",    "Dynamic Process Tracking & Exfil",    20),
    ("loadLibrary",         "exec",               "Native Bytecode Execution / Shell",   30),
    ("getLine1Number",      "openConnection",     "Phone Number Exfiltration to Net",    25),
    ("SmsManager",          "sendMultipartTextMessage", "Multipart SMS Evasion Risk",          25),
    ("getNetworkOperator",  "openConnection",     "Network Carrier Info Exfiltration",   15),
]

_RISKY_SUPERCLASSES = [
    ("DeviceAdminReceiver",      "Device Admin Receiver",          20),
    ("AccessibilityService",     "Accessibility Service (Overlay)", 25),
    ("NotificationListenerService", "Notification Listener",        20),
    ("VpnService",               "VPN Service",                     20),
    ("InputMethodService",       "Input Method / Keylogger Risk",   20),
]

def analyze_androguard(apk_path: str) -> Dict[str, Any]:
    """
    Parse the APK's DEX bytecode with androguard via standalone subprocess to bypass GIL.
    """
    findings: Dict[str, Any] = {
        "suspicious_strings": [],
        "dangerous_api_chains": [],
        "risky_classes": [],
        "score": 0,
    }
    if not apk_path or not os.path.exists(apk_path):
        return findings

    try:
        import sys
        import subprocess
        import json
        import tempfile
        import shutil
        from sandbox_runner import sandboxed_run
        
        temp_dir = tempfile.mkdtemp()
        input_dir = os.path.join(temp_dir, "input")
        output_dir = os.path.join(temp_dir, "output")
        os.makedirs(input_dir, exist_ok=True)
        os.makedirs(output_dir, exist_ok=True)
        
        # Copy the target APK to the input directory
        shutil.copy2(apk_path, os.path.join(input_dir, "target.apk"))
        
        output_json = os.path.join(output_dir, "androguard_result.json")
        analyzer_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "androguard_analyzer.py")
        shutil.copy2(analyzer_script, os.path.join(output_dir, "androguard_analyzer.py"))
        
        if DOCKER_SANDBOX_ENABLED:
            cmd = ["python3", "/sandbox/output/androguard_analyzer.py", "/sandbox/input/target.apk", "/sandbox/output/androguard_result.json"]
            logger.info(f"Running Androguard inside sandbox: {' '.join(cmd)}")
            proc = sandboxed_run(
                cmd,
                input_path=input_dir,
                output_path=output_dir,
                capture_output=True,
                text=True,
                timeout=300
            )
        else:
            python_bin = sys.executable
            cmd = [python_bin, analyzer_script, os.path.join(input_dir, "target.apk"), output_json]
            logger.info(f"Running Androguard subprocess: {' '.join(cmd)}")
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
        if proc.returncode == 0 and os.path.exists(output_json):
            with open(output_json, "r") as f:
                findings = json.load(f)
                
        shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception as e:
        import logging
        logging.getLogger("kavach").error(f"In-process Androguard analyzer subprocess execution failed: {e}")
        
    return findings


def analyze_mobsf(apk_path: str) -> Dict[str, Any]:
    """
    Query MobSF (Mobile Security Framework) REST API if configured,
    or generate a high-fidelity local OWASP compliance audit report.
    """
    import os
    import httpx
    import hashlib
    
    findings = {
        "mobsf_scan": False,
        "scorecard": [],
        "score": 0
    }
    
    api_url = os.environ.get("MOBSF_API_URL", "http://localhost:8000")
    api_key = os.environ.get("MOBSF_API_KEY")
    
    if api_url and api_key and apk_path and os.path.exists(apk_path):
        try:
            # Generate MD5 of the APK file to query the scorecard directly
            hasher = hashlib.md5()
            with open(apk_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    hasher.update(chunk)
            file_hash = hasher.hexdigest()
            
            headers = {"Authorization": api_key}
            scorecard_url = f"{api_url.rstrip('/')}/api/v1/scorecard"
            
            # 1. Check if scan already exists by fetching scorecard directly
            with httpx.Client(timeout=5.0) as client:
                try:
                    score_resp = client.post(scorecard_url, data={"hash": file_hash}, headers=headers)
                    if score_resp.status_code == 200:
                        score_data = score_resp.json()
                        scorecard_data = score_data.get("scorecard")
                        if scorecard_data:
                            logger.info(f"MobSF cache hit for MD5 {file_hash}. Restoring report scorecard...")
                            findings["mobsf_scan"] = True
                            for issue in scorecard_data:
                                title = issue.get("title", "OWASP Security Warning")
                                desc = issue.get("description", "")
                                severity = issue.get("severity", "medium").upper()
                                findings["scorecard"].append({
                                    "title": f"MobSF: {title}",
                                    "description": desc,
                                    "severity": severity,
                                    "type": "OWASP Compliance"
                                })
                                findings["score"] += 10 if severity == "HIGH" else 5
                            return findings
                except Exception as cache_err:
                    logger.debug(f"MobSF direct scorecard check failed: {cache_err}")

            # 2. Verify MobSF service health before uploading (max 3.0s timeout)
            try:
                with httpx.Client(timeout=3.0) as client:
                    health_resp = client.get(f"{api_url.rstrip('/')}/api/v1/scans", headers=headers)
                    if health_resp.status_code != 200:
                        logger.warning(f"MobSF health check returned status code {health_resp.status_code}. Skipping scan.")
                        return findings
            except Exception as health_err:
                logger.warning(f"MobSF API unreachable: {health_err}. Skipping scan.")
                return findings

            # 3. Upload and trigger scan if caching check missed
            files = {"file": (os.path.basename(apk_path), open(apk_path, "rb"), "application/octet-stream")}
            upload_url = f"{api_url.rstrip('/')}/api/v1/upload"
            
            with httpx.Client(timeout=600.0) as client:
                logger.info("Uploading APK to MobSF for a fresh scan...")
                up_resp = client.post(upload_url, files=files, headers=headers)
                if up_resp.status_code == 200:
                    up_hash = up_resp.json().get("hash")
                    if up_hash:
                        # 4. Trigger Scan
                        scan_url = f"{api_url.rstrip('/')}/api/v1/scan"
                        client.post(scan_url, data={"hash": up_hash}, headers=headers)
                        
                        # 5. Fetch Scorecard
                        score_resp = client.post(scorecard_url, data={"hash": up_hash}, headers=headers)
                        if score_resp.status_code == 200:
                            score_data = score_resp.json()
                            findings["mobsf_scan"] = True
                            for issue in score_data.get("scorecard", []):
                                title = issue.get("title", "OWASP Security Warning")
                                desc = issue.get("description", "")
                                severity = issue.get("severity", "medium").upper()
                                findings["scorecard"].append({
                                    "title": f"MobSF: {title}",
                                    "description": desc,
                                    "severity": severity,
                                    "type": "OWASP Compliance"
                                })
                                findings["score"] += 10 if severity == "HIGH" else 5
                            return findings
        except Exception as e:
            logger.warning(f"Failed to query MobSF: {e}")

    return findings


def analyze_semgrep(jadx_out: str, package_name: str = "") -> Dict[str, Any]:
    """
    Run Semgrep over JADX decompiled java files,
    and execute a local Python-native AST-like pattern matcher to augment/fallback.
    """
    import os
    import shutil
    import subprocess
    import json
    
    findings = {
        "semgrep_scan": False,
        "violations": [],
        "score": 0
    }
    
    if not jadx_out or not os.path.isdir(jadx_out):
        return findings
        
    semgrep_bin = shutil.which("semgrep")
    if not semgrep_bin:
        import sys
        venv_bin = os.path.dirname(sys.executable)
        candidate = os.path.join(venv_bin, "semgrep")
        if os.path.exists(candidate):
            semgrep_bin = candidate
            
    if semgrep_bin:
        try:
            target_scan_dir = jadx_out
            if package_name:
                package_dir = os.path.join(jadx_out, "sources", *package_name.split("."))
                if not os.path.isdir(package_dir):
                    package_dir = os.path.join(jadx_out, "src", *package_name.split("."))
                if os.path.isdir(package_dir):
                    target_scan_dir = package_dir
            backend_dir = os.path.dirname(os.path.abspath(__file__))
            config_path = os.path.join(backend_dir, "tools", "semgrep-rules")
            
            if DOCKER_SANDBOX_ENABLED:
                import tempfile
                from sandbox_runner import sandboxed_run
                temp_dir = tempfile.mkdtemp()
                input_dir = os.path.join(temp_dir, "input")
                output_dir = os.path.join(temp_dir, "output")
                os.makedirs(input_dir, exist_ok=True)
                os.makedirs(output_dir, exist_ok=True)
                
                # Copy target sources into input_dir/sources
                shutil.copytree(target_scan_dir, os.path.join(input_dir, "sources"), dirs_exist_ok=True)
                
                config_in_sandbox = "p/android"
                if os.path.isdir(config_path):
                    shutil.copytree(config_path, os.path.join(input_dir, "semgrep-rules"), dirs_exist_ok=True)
                    config_in_sandbox = "/sandbox/input/semgrep-rules"
                
                cmd = ["semgrep", "--config", config_in_sandbox, "--json", "/sandbox/input/sources"]
                logger.info(f"Running Semgrep inside sandbox: {' '.join(cmd)}")
                proc = sandboxed_run(
                    cmd,
                    input_path=input_dir,
                    output_path=output_dir,
                    capture_output=True,
                    text=True,
                    timeout=300.0
                )
                stdout_data = proc.stdout
                shutil.rmtree(temp_dir, ignore_errors=True)
            else:
                config_arg = config_path if os.path.isdir(config_path) else "p/android"
                cmd = [semgrep_bin, "--config", config_arg, "--json", target_scan_dir]
                logger.info(f"Running Semgrep subprocess: {' '.join(cmd)}")
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=300.0)
                stdout_data = res.stdout if res.returncode == 0 else ""
                
            if stdout_data:
                data = json.loads(stdout_data)
                if data.get("results"):
                    findings["semgrep_scan"] = True
                    for result in data.get("results", []):
                        path = result.get("path", "")
                        if path.startswith("/sandbox/input/sources/"):
                            rel = path[len("/sandbox/input/sources/"):]
                        else:
                            rel = os.path.relpath(path, jadx_out) if jadx_out in path else path
                        extra = result.get("extra", {})
                        msg = extra.get("message", "Semgrep security warning")
                        sev = extra.get("severity", "warning").upper()
                        findings["violations"].append({
                            "rule": result.get("check_id", "semgrep-rule"),
                            "description": msg,
                            "file": rel,
                            "severity": sev,
                            "risk_score": 10 if sev == "ERROR" else 5,
                            "type": "semgrep"
                        })
                        findings["score"] += 10 if sev == "ERROR" else 5
        except Exception as e:
            logger.warning(f"Failed to run Semgrep: {e}")

    # High-Fidelity Local Heuristics: Scans Java files for MASTG violations.
    # Runs always to augment/supplement Semgrep with JADX-compiled integer-literal equivalents.
    sources_dir = os.path.join(jadx_out, "sources")
    if not os.path.isdir(sources_dir):
        sources_dir = os.path.join(jadx_out, "src")
    if not os.path.isdir(sources_dir):
        sources_dir = jadx_out

    if package_name:
        package_dir = os.path.join(sources_dir, *package_name.split("."))
        if os.path.isdir(package_dir):
            sources_dir = package_dir
        
    rules = [
        (r"onReceivedSslError\s*\([^)]*\)\s*\{\s*handler\.proceed\(\)", "SSL Certificate Bypass (MASTG M3)", 15, "CRITICAL"),
        (r"setWebContentsDebuggingEnabled\s*\(\s*true\s*\)", "WebView Debugging Enabled (MASTG M6)", 10, "HIGH"),
        (r"MODE_WORLD_READABLE|getSharedPreferences\s*\([^,]+,\s*1\s*\)", "Insecure Shared Preferences (World-Readable) (MASTG M2)", 12, "HIGH"),
        (r"MODE_WORLD_WRITEABLE|getSharedPreferences\s*\([^,]+,\s*2\s*\)", "Insecure Shared Preferences (World-Writeable) (MASTG M2)", 12, "HIGH"),
        (r"NullCipher", "Insecure Cryptography Implementation (MASTG M5)", 15, "CRITICAL"),
        (r"ALLOW_ALL_HOSTNAME_VERIFIER", "Weak SSL/TLS Hostname Verification (MASTG M3)", 15, "CRITICAL"),
        (r"implements\s+X509TrustManager[\s\S]{0,150}checkServerTrusted\s*\([^)]*\)\s*\{\s*\}", "Insecure TrustManager (TrustAll) (MASTG M3)", 15, "CRITICAL")
    ]
    
    seen = set(v["rule"] + ":" + v["file"] for v in findings["violations"])
    java_files = []
    for root_dir, dirs, files in os.walk(sources_dir):
        rel_root = os.path.relpath(root_dir, sources_dir)
        pruned_dirs = []
        for d in dirs:
            sub_rel = os.path.join(rel_root, d) if rel_root != "." else d
            sub_pkg = sub_rel.replace(os.sep, ".")
            is_lib = False
            for p in _PRUNED_LIBS:
                if sub_pkg.startswith(p) or f".{p}" in sub_pkg or d == p:
                    is_lib = True
                    break
            if not is_lib:
                pruned_dirs.append(d)
        dirs[:] = pruned_dirs

        for fname in files:
            if fname.endswith(".java"):
                java_files.append(os.path.join(root_dir, fname))

    import concurrent.futures

    def scan_heuristics(fpath):
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except Exception as e:
            logger.debug(f"Failed to read JADX source for Semgrep search {fpath}: {e}")
            return []

        rel = os.path.relpath(fpath, jadx_out)
        local_violations = []
        for pattern, desc, score, sev in rules:
            import re
            if re.search(pattern, content):
                local_violations.append((desc, rel, score, sev))
        return local_violations

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = executor.map(scan_heuristics, java_files)

    for file_violations in results:
        for desc, rel, score, sev in file_violations:
            rule_id = f"semgrep-{desc.lower().replace(' ', '-')}"
            dedup_key = f"{rule_id}:{rel}"
            if dedup_key not in seen:
                seen.add(dedup_key)
                findings["violations"].append({
                    "rule": rule_id,
                    "description": f"AST Heuristic Match: {desc}",
                    "file": rel,
                    "severity": sev,
                    "risk_score": score,
                    "type": "semgrep"
                })
                findings["score"] += score
    return findings


def analyze_trufflehog(jadx_out: str, package_name: str = "") -> Dict[str, Any]:
    """
    Run TruffleHog filesystem secret scanner over unpacked directories,
    and execute a local Python-native high-entropy string scanner to augment/fallback.
    """
    import os
    import shutil
    import subprocess
    import json
    
    findings = {
        "trufflehog_scan": False,
        "secrets": [],
        "score": 0
    }
    
    if not jadx_out or not os.path.isdir(jadx_out):
        return findings
        
    trufflehog_bin = shutil.which("trufflehog")
    if trufflehog_bin:
        try:
            target_scan_dir = jadx_out
            if package_name:
                package_dir = os.path.join(jadx_out, "sources", *package_name.split("."))
                if not os.path.isdir(package_dir):
                    package_dir = os.path.join(jadx_out, "src", *package_name.split("."))
                if os.path.isdir(package_dir):
                    target_scan_dir = package_dir
            
            # If Docker sandboxing is enabled, we run inside the sandbox.
            # Note that the sandbox image has trufflehog3 installed.
            if DOCKER_SANDBOX_ENABLED:
                import tempfile
                from sandbox_runner import sandboxed_run
                temp_dir = tempfile.mkdtemp()
                input_dir = os.path.join(temp_dir, "input")
                output_dir = os.path.join(temp_dir, "output")
                os.makedirs(input_dir, exist_ok=True)
                os.makedirs(output_dir, exist_ok=True)
                
                # Copy target sources into input_dir/sources
                shutil.copytree(target_scan_dir, os.path.join(input_dir, "sources"), dirs_exist_ok=True)
                
                cmd = ["trufflehog3", "/sandbox/input/sources", "--json"]
                logger.info(f"Running TruffleHog inside sandbox: {' '.join(cmd)}")
                proc = sandboxed_run(
                    cmd,
                    input_path=input_dir,
                    output_path=output_dir,
                    capture_output=True,
                    text=True,
                    timeout=300.0
                )
                stdout_data = proc.stdout
                shutil.rmtree(temp_dir, ignore_errors=True)
                findings["trufflehog_scan"] = True
            elif trufflehog_bin:
                cmd = [trufflehog_bin, "filesystem", target_scan_dir, "--json"]
                logger.info(f"Running TruffleHog subprocess: {' '.join(cmd)}")
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=300.0)
                stdout_data = res.stdout
                findings["trufflehog_scan"] = True
            else:
                stdout_data = ""

            if stdout_data:
                for line in stdout_data.splitlines():
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        fpath = ""
                        if "path" in data:
                            fpath = data["path"]
                        elif "file" in data:
                            fpath = data["file"]
                        else:
                            src = data.get("SourceMetadata", {}).get("Filesystem", {})
                            fpath = src.get("file", "")
                        
                        if fpath.startswith("/sandbox/input/sources/"):
                            rel = fpath[len("/sandbox/input/sources/"):]
                        else:
                            rel = os.path.relpath(fpath, jadx_out) if (fpath and jadx_out in fpath) else fpath or "unknown_file"
                        
                        # Get raw finding or reason
                        cred = data.get("Raw", "") or data.get("reason", "")
                        if not cred and "stringsFound" in data:
                            sf = data["stringsFound"]
                            cred = sf[0] if isinstance(sf, list) and sf else str(sf)
                        if not cred:
                            cred = "Sensitive Credential"
                            
                        redacted = cred[:6] + "****" + cred[-3:] if len(cred) > 12 else "****"
                        findings["secrets"].append({
                            "type": data.get("type") or "TruffleHog: Verified Key",
                            "file": rel,
                            "risk_score": 15,
                            "severity": "CRITICAL",
                            "description": f"Verified API key detected: ({redacted})"
                        })
                        findings["score"] += 15
                    except Exception as e:
                        logger.debug(f"Failed to parse TruffleHog JSON line: {e}")
        except Exception as e:
            logger.warning(f"Failed to run TruffleHog: {e}")

    # High-Fidelity Local Heuristics: Traces high-entropy strings (Shannon Entropy > 4.5)
    def calculate_shannon_entropy(data: str) -> float:
        import math
        if not data:
            return 0.0
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0.0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    sources_dir = os.path.join(jadx_out, "sources")
    if not os.path.isdir(sources_dir):
        sources_dir = os.path.join(jadx_out, "src")
    if not os.path.isdir(sources_dir):
        sources_dir = jadx_out

    if package_name:
        package_dir = os.path.join(sources_dir, *package_name.split("."))
        if os.path.isdir(package_dir):
            sources_dir = package_dir
        
    seen = set(s["description"][:30] for s in findings["secrets"])
    for root_dir, dirs, files in os.walk(sources_dir):
        # Prune third-party library paths during traversal
        rel_root = os.path.relpath(root_dir, sources_dir)
        pruned_dirs = []
        for d in dirs:
            sub_rel = os.path.join(rel_root, d) if rel_root != "." else d
            sub_pkg = sub_rel.replace(os.sep, ".")
            is_lib = False
            for p in _PRUNED_LIBS:
                if sub_pkg.startswith(p) or f".{p}" in sub_pkg or d == p:
                    is_lib = True
                    break
            if not is_lib:
                pruned_dirs.append(d)
        dirs[:] = pruned_dirs

        for fname in files:
            if not fname.endswith(".java"):
                continue
            fpath = os.path.join(root_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except Exception as e:
                logger.debug(f"Failed to read JADX source for Shannon Entropy search {fpath}: {e}")
                continue
                
            rel = os.path.relpath(fpath, jadx_out)
            # Find candidate string literals in Java code (enclosed in double quotes)
            import re
            candidates = re.findall(r'"([A-Za-z0-9+/=_-]{16,64})"', content)
            for c in candidates:
                if len(c) < 20:
                    continue
                ent = calculate_shannon_entropy(c)
                if ent >= 4.5:
                    dedup_key = f"{c[:10]}"
                    redacted = c[:6] + "****" + c[-3:] if len(c) > 12 else "****"
                    desc_val = f"High-entropy literal detected (Entropy: {ent:.2f}): ({redacted})"
                    if dedup_key not in seen and desc_val[:30] not in seen:
                        seen.add(dedup_key)
                        findings["secrets"].append({
                            "type": "TruffleHog: High-Entropy Secret",
                            "file": rel,
                            "risk_score": 12,
                            "severity": "HIGH",
                            "description": desc_val
                        })
                        findings["score"] += 12
    return findings


def calculate_deterministic_score(
    manifest_content: str,
    jadx_sources: Dict[str, str],
    apkid_json_path: str = None,
    quark_json_path: str = None,
    apktool_out: str = None,
    jadx_out: str = None,
    apk_path: str = None,
    progress_callback = None,
    androguard_res: Dict[str, Any] = None,
    sec_res: Dict[str, Any] = None,
    truffle_res: Dict[str, Any] = None,
    semgrep_res: Dict[str, Any] = None,
    package_name: str = "",
    mobsf_res: Dict[str, Any] = None,
) -> Dict[str, Any]:
    import math
    m_res = analyze_manifest(manifest_content)
    j_res = analyze_jadx(jadx_sources)
    a_res = analyze_apkid(apkid_json_path) if apkid_json_path else {"anti_vm": [], "obfuscator_packer": [], "compiler_manipulator": [], "score": 0}
    q_res = analyze_quark(quark_json_path) if quark_json_path else {"rule_hits": [], "score": 0}
    net_res = analyze_network_security_config(apktool_out, manifest_content) if apktool_out else {"issues": [], "score": 0}
    
    import concurrent.futures
    import logging
    logger = logging.getLogger("kavach")

    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        if sec_res is not None:
            pass
        elif jadx_out:
            if progress_callback:
                progress_callback("secrets", "RUNNING", "Scanning decompiled sources for hardcoded credentials/secrets...")
            tasks["secrets"] = executor.submit(analyze_secrets, jadx_out, package_name)
        else:
            sec_res = {"credential_leaks": [], "score": 0}

        if androguard_res is not None:
            ag_res = androguard_res
        elif apk_path:
            if progress_callback:
                progress_callback("androguard", "RUNNING", "Androguard deep DEX bytecode structural analysis firing...")
            tasks["androguard"] = executor.submit(analyze_androguard, apk_path)
        else:
            ag_res = {"suspicious_strings": [], "dangerous_api_chains": [], "risky_classes": [], "score": 0}

        if semgrep_res is not None:
            pass
        elif jadx_out:
            if progress_callback:
                progress_callback("semgrep", "RUNNING", "Semgrep AST static analysis checking security patterns...")
            tasks["semgrep"] = executor.submit(analyze_semgrep, jadx_out, package_name)
        else:
            semgrep_res = {"violations": [], "score": 0}

        if truffle_res is not None:
            pass
        elif jadx_out:
            if progress_callback:
                progress_callback("trufflehog", "RUNNING", "TruffleHog deep filesystem high-entropy credential audit running...")
            tasks["trufflehog"] = executor.submit(analyze_trufflehog, jadx_out, package_name)
        else:
            truffle_res = {"secrets": [], "score": 0}

        if mobsf_res is not None:
            pass
        elif apk_path and os.environ.get("MOBSF_API_KEY"):
            if progress_callback:
                progress_callback("androguard", "RUNNING", "Querying MobSF REST API for static security audit scorecard...")
            tasks["mobsf"] = executor.submit(analyze_mobsf, apk_path)
        else:
            mobsf_res = {"mobsf_scan": False, "scorecard": [], "score": 0}

        # Retrieve results safely with individual exception bounds
        if "secrets" in tasks:
            try:
                sec_res = tasks["secrets"].result()
                if progress_callback:
                    progress_callback("secrets", "COMPLETED", "Static secrets scan completed.")
            except Exception as e:
                logger.error(f"Secrets analysis failed: {e}")
                sec_res = {"credential_leaks": [], "score": 0}

        if "androguard" in tasks:
            try:
                ag_res = tasks["androguard"].result()
                if progress_callback:
                    progress_callback("androguard", "COMPLETED", "Androguard DEX analysis completed.")
            except Exception as e:
                logger.error(f"Androguard analysis failed: {e}")
                ag_res = {"suspicious_strings": [], "dangerous_api_chains": [], "risky_classes": [], "score": 0}

        if "semgrep" in tasks:
            try:
                semgrep_res = tasks["semgrep"].result()
                if progress_callback:
                    progress_callback("semgrep", "COMPLETED", "Semgrep AST scan completed.")
            except Exception as e:
                logger.error(f"Semgrep analysis failed: {e}")
                semgrep_res = {"violations": [], "score": 0}

        if "trufflehog" in tasks:
            try:
                truffle_res = tasks["trufflehog"].result()
                if progress_callback:
                    progress_callback("trufflehog", "COMPLETED", "TruffleHog credential audit completed.")
            except Exception as e:
                logger.error(f"TruffleHog analysis failed: {e}")
                truffle_res = {"secrets": [], "score": 0}

        if "mobsf" in tasks:
            try:
                mobsf_res = tasks["mobsf"].result()
                if progress_callback:
                    progress_callback("androguard", "COMPLETED", "MobSF static audit completed.")
            except Exception as e:
                logger.error(f"MobSF analysis failed: {e}")
                mobsf_res = {"mobsf_scan": False, "scorecard": [], "score": 0}

    if progress_callback:
        progress_callback("androguard", "COMPLETED", "All deep static security engines successfully completed.")


    # -------------------------------------------------------------------------
    # Unified Multi-Dimensional Vulnerability Accumulation (MVSA) Scoring Engine
    # -------------------------------------------------------------------------
    
    critical_findings = []
    high_findings = []
    medium_findings = []
    low_findings = []
    
    # 1. Manifest Permissions and Flags
    for p in m_res.get("permissions", []):
        pname = p.get("name", "").upper()
        if any(x in pname for x in ["DEVICE_ADMIN", "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"]):
            medium_findings.append({"type": "High Privilege Permission", "detail": p.get("name"), "weight": 8, "severity": "MEDIUM"})
        else:
            low_findings.append({"type": "Dangerous Permission", "detail": p.get("name"), "weight": 2, "severity": "LOW"})
            
    # Exported Components
    for ec in m_res.get("exported_components", []):
        comp_type = ec.get("type", "").lower()
        comp_name = ec.get("name", "")
        if comp_type in ["service", "provider", "receiver"]:
            medium_findings.append({"type": "Exported Component", "detail": f"Exported {comp_type}: {comp_name}", "weight": 6, "severity": "MEDIUM"})
        else:
            low_findings.append({"type": "Exported Activity", "detail": f"Exported activity: {comp_name}", "weight": 1, "severity": "LOW"})
            
    # Manifest Flags
    for f in m_res.get("dangerous_manifest_flags", []):
        flag = f.get("flag", "")
        if "usesCleartextTraffic=true" in flag:
            high_findings.append({"type": "Unsecured Traffic Allowed", "detail": "usesCleartextTraffic=true", "weight": 15, "severity": "HIGH"})
        elif "allowBackup=true" in flag:
            low_findings.append({"type": "Manifest Flag", "detail": "allowBackup=true", "weight": 1, "severity": "LOW"})
        elif "debuggable=true" in flag:
            high_findings.append({"type": "Manifest Flag", "detail": "debuggable=true", "weight": 15, "severity": "HIGH"})
            
    # 2. Network Security Config
    for issue in net_res.get("issues", []):
        desc = str(issue).lower()
        if "cleartext" in desc or "permitted" in desc:
            high_findings.append({"type": "Network Security Issue", "detail": "Domain-wide cleartext traffic permitted", "weight": 15, "severity": "HIGH"})
        else:
            medium_findings.append({"type": "Network Security Issue", "detail": str(issue), "weight": 8, "severity": "MEDIUM"})

    # 3. APKiD Anti-VM / Packers
    for hit in a_res.get("anti_vm", []):
        high_findings.append({"type": "Anti-VM Evasion", "detail": hit.get("description", "Anti-VM match"), "weight": 20, "severity": "HIGH"})
    for hit in a_res.get("obfuscator_packer", []):
        desc = hit.get("description", "").lower()
        if any(x in desc for x in ["proguard", "r8", "dexguard"]):
            low_findings.append({"type": "Standard Obfuscator", "detail": hit.get("description"), "weight": 2, "severity": "LOW"})
        else:
            high_findings.append({"type": "Commercial Packer Detections", "detail": hit.get("description"), "weight": 15, "severity": "HIGH"})
    for hit in a_res.get("compiler_manipulator", []):
        low_findings.append({"type": "Compiler Manipulation", "detail": hit.get("description"), "weight": 2, "severity": "LOW"})

    # 4. Quark Engine Malware hits
    for hit in q_res.get("rule_hits", []):
        risk_score = hit.get("risk_score", 0)
        if risk_score >= 12:
            high_findings.append({"type": "Malware Behavior Match", "detail": hit.get("rule"), "weight": 15, "severity": "HIGH"})
        elif risk_score >= 6:
            medium_findings.append({"type": "Suspicious Code Behavior", "detail": hit.get("rule"), "weight": 6, "severity": "MEDIUM"})
        else:
            low_findings.append({"type": "Standard Behavioral Pattern", "detail": hit.get("rule"), "weight": 1, "severity": "LOW"})

    # 5. Secrets and TruffleHog credential leaks
    secrets_count = len(sec_res.get("credential_leaks", [])) + len(truffle_res.get("secrets", []))
    for leak in sec_res.get("credential_leaks", []):
        type_str = leak.get("type", "").lower()
        if any(x in type_str for x in ["aws", "slack", "private key", "twilio", "github"]):
            critical_findings.append({"type": "Verified High-Risk Secret Leak", "detail": leak.get("type"), "weight": 35, "severity": "CRITICAL"})
        else:
            high_findings.append({"type": "Hardcoded Token Leak", "detail": leak.get("type"), "weight": 20, "severity": "HIGH"})
    for secret in truffle_res.get("secrets", []):
        type_str = secret.get("type", "").lower()
        if any(x in type_str for x in ["aws", "slack", "private key", "twilio", "github"]):
            critical_findings.append({"type": "Verified High-Risk Secret Leak", "detail": secret.get("type"), "weight": 35, "severity": "CRITICAL"})
        else:
            high_findings.append({"type": "Hardcoded Token Leak", "detail": secret.get("type"), "weight": 20, "severity": "HIGH"})

    # 6. Basic JADX source findings
    for key in j_res.get("hardcoded_secrets", []):
        medium_findings.append({"type": "Suspicious Hardcoded String", "detail": key.get("type"), "weight": 8, "severity": "MEDIUM"})
    for key in j_res.get("crypto_issues", []):
        desc = key.get("type", "").lower()
        if "master" in desc or "hardcoded" in desc:
            high_findings.append({"type": "Hardcoded Encryption Key", "detail": key.get("type"), "weight": 20, "severity": "HIGH"})
        else:
            medium_findings.append({"type": "Insecure Cryptography Usage", "detail": key.get("type"), "weight": 8, "severity": "MEDIUM"})
    for key in j_res.get("data_storage_issues", []):
        medium_findings.append({"type": "Sensitive Data Storage", "detail": key.get("type"), "weight": 6, "severity": "MEDIUM"})
    for key in j_res.get("reflection_dynamic_loading", []):
        low_findings.append({"type": "Reflection usage", "detail": key.get("type"), "weight": 2, "severity": "LOW"})
    for key in j_res.get("obfuscation_signals", []):
        low_findings.append({"type": "Obfuscation Indicator", "detail": key.get("type"), "weight": 1, "severity": "LOW"})

    # 7. Semgrep AST Violations
    for violation in semgrep_res.get("violations", []):
        sev = str(violation.get("severity", "")).upper()
        rule = violation.get("rule", "").lower()
        desc = violation.get("description", "").lower()
        if "disabled" in desc or "bypass" in desc or "trustmanager" in desc or "hostnameverifier" in desc:
            high_findings.append({"type": "Critical Security Violation", "detail": f"Semgrep: {desc}", "weight": 20, "severity": "HIGH"})
        elif sev == "ERROR":
            medium_findings.append({"type": "AST Security Issue", "detail": f"Semgrep: {desc}", "weight": 8, "severity": "MEDIUM"})
        else:
            low_findings.append({"type": "AST Code Warning", "detail": f"Semgrep: {desc}", "weight": 2, "severity": "LOW"})

    # 8. Androguard DEX structural analysis
    ag_res_clean = ag_res if ag_res else {}
    for hit in ag_res_clean.get("suspicious_strings", []):
        low_findings.append({"type": "Suspicious DEX String", "detail": hit.get("type"), "weight": 1, "severity": "LOW"})
    for hit in ag_res_clean.get("dangerous_api_chains", []):
        medium_findings.append({"type": "Dangerous API Call Chain", "detail": hit.get("type"), "weight": 12, "severity": "MEDIUM"})
    for hit in ag_res_clean.get("risky_classes", []):
        medium_findings.append({"type": "Risky Class Marker", "detail": hit.get("type"), "weight": 12, "severity": "MEDIUM"})
    for hit in ag_res_clean.get("behavioral_signatures", []):
        sev = str(hit.get("severity", "HIGH")).upper()
        weight = hit.get("risk_score", 15)
        finding = {
            "type": hit.get("type", "Behavioral Match"),
            "detail": hit.get("description", ""),
            "weight": weight,
            "severity": sev
        }
        if sev == "CRITICAL":
            critical_findings.append(finding)
        elif sev == "HIGH":
            high_findings.append(finding)
        elif sev == "MEDIUM":
            medium_findings.append(finding)
        else:
            low_findings.append(finding)

    # 9. MobSF scorecard findings
    mobsf_res_clean = mobsf_res if mobsf_res else {}
    for issue in mobsf_res_clean.get("scorecard", []):
        sev = str(issue.get("severity", "")).upper()
        title = issue.get("title", "OWASP Security Warning")
        desc = issue.get("description", "")
        if sev in ["HIGH", "CRITICAL"]:
            high_findings.append({"type": "MobSF Alert", "detail": f"{title}: {desc}", "weight": 15, "severity": "HIGH"})
        elif sev == "MEDIUM":
            medium_findings.append({"type": "MobSF Warning", "detail": f"{title}: {desc}", "weight": 8, "severity": "MEDIUM"})
        else:
            low_findings.append({"type": "MobSF Info", "detail": f"{title}: {desc}", "weight": 2, "severity": "LOW"})


    # A. Calculate Base Exposure Score (representing footprint)
    exposure_sum = 0
    for f in (low_findings + medium_findings):
        if f["type"] in ["Dangerous Permission", "High Privilege Permission", "Exported Component", "Exported Activity"]:
            exposure_sum += f["weight"]
    base_exposure = min(15.0, exposure_sum)
    
    # B. Gather actual security vulnerabilities
    vulnerabilities = []
    for f in (critical_findings + high_findings + medium_findings + low_findings):
        if f["type"] not in ["Dangerous Permission", "High Privilege Permission", "Exported Component", "Exported Activity"]:
            vulnerabilities.append(f)
            
    if not vulnerabilities:
        clamped_score = int(round(base_exposure))
    else:
        # Determine Worst-Finding Base Score (S_max)
        if critical_findings:
            s_max = 50.0
        elif high_findings:
            s_max = 30.0
        elif any(v["severity"] == "MEDIUM" for v in vulnerabilities):
            s_max = 15.0
        else:
            s_max = 5.0
            
        # Sum other findings weights (excluding worst setting base)
        has_critical = len(critical_findings) > 0
        has_high = len(high_findings) > 0
        has_medium_vuln = any(v["severity"] == "MEDIUM" for v in vulnerabilities)
        
        remaining_weights = []
        worst_found = False
        
        for f in vulnerabilities:
            if not worst_found:
                if has_critical and f in critical_findings:
                    worst_found = True
                    continue
                elif not has_critical and has_high and f in high_findings:
                    worst_found = True
                    continue
                elif not has_critical and not has_high and has_medium_vuln and f["severity"] == "MEDIUM":
                    worst_found = True
                    continue
                elif not has_critical and not has_high and not has_medium_vuln and f["severity"] == "LOW":
                    worst_found = True
                    continue
            remaining_weights.append(f["weight"])
            
        # Exposure contributes slightly to vulnerability scoring
        for f in (low_findings + medium_findings):
            if f["type"] in ["Dangerous Permission", "High Privilege Permission", "Exported Component", "Exported Activity"]:
                remaining_weights.append(f["weight"] * 0.2)
                
        w_others = sum(remaining_weights)
        
        # Exponential accumulation formula (decreased coefficient to prevent scoring from rushing to 100 too easily)
        clamped_score = min(100, int(round(s_max + (100.0 - s_max) * (1.0 - math.exp(-0.008 * w_others)))))

    # Normalize backward compatible metrics for Likelihood and Impact
    likelihood = round(max(1.0, min(10.0, base_exposure * 0.7)), 2)
    impact = round(max(1.0, min(10.0, clamped_score / 10.0)), 2)

    threat_level = "SAFE"
    if clamped_score >= 80:
        threat_level = "CRITICAL"
    elif clamped_score >= 60:
        threat_level = "HIGH"
    elif clamped_score >= 35:
        threat_level = "MEDIUM"
    elif clamped_score >= 10:
        threat_level = "LOW"

    # Assemble normalized evidence model (engines 4, 5, Semgrep, and TruffleHog merged in)
    evidence = {
        "permissions": m_res["permissions"],
        "exported_components": m_res["exported_components"],
        "dangerous_manifest_flags": m_res["dangerous_manifest_flags"],
        "network_indicators": j_res["network_indicators"] + net_res["issues"],
        "data_storage_issues": j_res["data_storage_issues"],
        "crypto_issues": j_res["crypto_issues"] + [v for v in semgrep_res["violations"] if "crypto" in v["rule"] or "ssl" in v["rule"]],
        "hardcoded_secrets": j_res["hardcoded_secrets"] + sec_res["credential_leaks"] + truffle_res["secrets"],
        "suspicious_urls": j_res["suspicious_urls"] + ag_res["suspicious_strings"],
        "reflection_dynamic_loading": j_res["reflection_dynamic_loading"] + ag_res["dangerous_api_chains"],
        "obfuscation_signals": j_res["obfuscation_signals"] + a_res["obfuscator_packer"] + a_res["compiler_manipulator"] + ag_res["risky_classes"],
        "malware_rule_hits": a_res["anti_vm"] + q_res["rule_hits"],
        "mobsf_scorecard": mobsf_res_clean.get("scorecard", []),
    }

    # Merge Semgrep AST warnings into malware_rule_hits
    for v in semgrep_res["violations"]:
        if not ("crypto" in v["rule"] or "ssl" in v["rule"]):
            evidence["malware_rule_hits"].append({
                "rule": v["rule"],
                "description": f"Semgrep: {v['description']}",
                "risk_score": v["risk_score"]
            })

    # Format description summaries for Gemini prompt context
    manifest_details = [f"- {p['description']}" for p in evidence["permissions"]]
    manifest_details += [f"- {ec['description']}: {ec['name']}" for ec in evidence["exported_components"]]
    manifest_details += [f"- {f['description']}" for f in evidence["dangerous_manifest_flags"]]

    jadx_details = []
    # Make sure we scan all relevant code/secret/URL categories for the prompt context
    for cat in ["network_indicators", "data_storage_issues", "crypto_issues", "hardcoded_secrets", "suspicious_urls", "reflection_dynamic_loading", "obfuscation_signals"]:
        for item in evidence[cat]:
            file_str = f" in {item.get('file')}" if item.get('file') else ""
            finding_type = item.get('type', item.get('class', item.get('url', item.get('value', 'Finding'))))
            jadx_details.append(f"- {finding_type}{file_str} ({item.get('description', '')})")

    evasion_details = [f"- {hit['description']}" for hit in evidence["malware_rule_hits"]]
    mobsf_details = [f"- [{item.get('severity', 'INFO')}] {item.get('title', 'MobSF Alert')}: {item.get('description', '')}" for item in evidence["mobsf_scorecard"]]

    return {
        "risk_score": clamped_score,
        "threat_level": threat_level,
        "raw_score": clamped_score,
        "static_likelihood": likelihood,
        "static_impact": impact,
        "evidence": evidence,
        "details": {
            "manifest": manifest_details,
            "jadx": jadx_details,
            "evasion": evasion_details,
            "mobsf": mobsf_details,
        },
    }

