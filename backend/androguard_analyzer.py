#!/usr/bin/env python3
"""
Standalone Androguard Analyzer.
Runs bytecode analysis on an APK and outputs findings to a JSON file.
Bypasses GIL lock contention on the Uvicorn parent process.
"""
import os
import sys
import json
import re

# Add backend directory to path just in case
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat

_STR_PATTERNS = [
    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?[/\w]*", "Hardcoded IP URL",         15),
    (r"https?://[a-zA-Z0-9-]+\.onion",                                  "Tor .onion C2 URL",       30),
    (r"https?://[a-zA-Z0-9]+\.ngrok\.io",                               "ngrok Tunnel URL",        20),
    (r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", "Long Base64 Blob", 8),
    (r"127\.0\.0\.1",                                                    "Loopback Listener Reference", 10),
    (r"/system/bin/sh|/system/xbin/su|/bin/sh",                          "Shell Command Binary Reference", 25),
    (r"\.dex|\.jar|\.so",                                                "Dynamic Executable File Target", 15),
]

_DANGEROUS_API_CHAINS = [
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
    ("SimTelephoneManager", "sendMultipartTextMessage", "Multipart SMS Evasion Risk",     25),
    ("getNetworkOperator",  "openConnection",     "Network Carrier Info Exfiltration",   15),
]

_RISKY_SUPERCLASSES = [
    ("DeviceAdminReceiver",      "Device Admin Receiver",          20),
    ("AccessibilityService",     "Accessibility Service (Overlay)", 25),
    ("NotificationListenerService", "Notification Listener",        20),
    ("VpnService",               "VPN Service",                     20),
    ("InputMethodService",       "Input Method / Keylogger Risk",   20),
]

def run_analysis(apk_path: str, output_path: str):
    findings = {
        "suspicious_strings": [],
        "dangerous_api_chains": [],
        "risky_classes": [],
        "score": 0,
    }

    try:
        a = APK(apk_path)
        d_list = []
        for dex in a.get_all_dex():
            df = DalvikVMFormat(dex)
            d_list.append(df)
    except Exception as e:
        # Save empty findings if APK parsing fails
        with open(output_path, "w") as f:
            json.dump(findings, f)
        sys.exit(0)

    # 1. Suspicious strings using d.get_strings() (O(1) string table lookup with fast C-optimized pre-filter)
    seen_strings = set()
    for d in d_list:
        if len(findings["suspicious_strings"]) >= 100:
            break
        for val_raw in d.get_strings():
            if len(findings["suspicious_strings"]) >= 100:
                break
            if isinstance(val_raw, bytes):
                val = val_raw.decode('utf-8', errors='ignore')
            else:
                val = str(val_raw)
                
            if len(val) < 12:
                continue
                
            # Quick C-optimized pre-filter to bypass 99% of normal strings without regular expressions
            if not any(x in val for x in ("://", "127.0.0.1", "/bin/", ".dex", ".jar", ".so", "==", "=")) and len(val) < 40:
                continue
                
            for pat, label, sc in _STR_PATTERNS:
                if re.search(pat, val) and val not in seen_strings:
                    # Filter out standard Dalvik class descriptors to avoid Base64 false positives
                    if label == "Long Base64 Blob":
                        if val.startswith("L") and val.endswith(";"):
                            continue
                        if "/" in val and not any(x in val for x in ("+", "=")):
                            if re.match(r"^L?[a-zA-Z0-9_]+(/[a-zA-Z0-9_]+)+;?$", val):
                                continue
                    seen_strings.add(val)
                    findings["suspicious_strings"].append({
                        "type": label,
                        "value": val[:120],
                        "risk_score": sc,
                        "severity": "HIGH",
                        "description": f"{label} found in bytecode constant: {val[:60]}"
                    })
                    findings["score"] += sc
                    break

    # 2. Dangerous API Chains (O(1) exact name lookup using a pre-built set to prevent slow iterative scans)
    available_methods = set()
    for d in d_list:
        try:
            for cls in d.get_classes():
                for m in cls.get_methods():
                    m_name = m.name
                    if isinstance(m_name, bytes):
                        m_name = m_name.decode('utf-8', errors='ignore')
                    else:
                        m_name = str(m_name or "")
                    available_methods.add(m_name)
        except Exception:
            pass

    for read_api, write_api, label, score in _DANGEROUS_API_CHAINS:
        if read_api in available_methods and write_api in available_methods:
            findings["dangerous_api_chains"].append({
                "type": label,
                "risk_score": score,
                "severity": "CRITICAL" if score >= 25 else "HIGH",
                "description": f"API chain detected: {read_api} → {write_api} ({label})"
            })
            findings["score"] += score

    # 3. Risky Superclasses
    for d in d_list:
        try:
            for cls in d.get_classes():
                sup_raw = cls.get_superclassname()
                if isinstance(sup_raw, bytes):
                    sup = sup_raw.decode('utf-8', errors='ignore')
                else:
                    sup = str(sup_raw or "")
                    
                for risky_cls, label, score in _RISKY_SUPERCLASSES:
                    if risky_cls in sup:
                        cls_name_raw = cls.name
                        if isinstance(cls_name_raw, bytes):
                            class_name = cls_name_raw.decode('utf-8', errors='ignore')
                        else:
                            class_name = str(cls_name_raw or "")
                        class_name = class_name.replace("/", ".").strip("L;")
                        findings["risky_classes"].append({
                            "class": class_name,
                            "type": label,
                            "risk_score": score,
                            "severity": "HIGH",
                            "description": f"Class `{class_name}` extends {risky_cls} ({label})"
                        })
                        findings["score"] += score
        except Exception:
            pass

    with open(output_path, "w") as f:
        json.dump(findings, f)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: androguard_analyzer.py <apk_path> <output_json_path>")
        sys.exit(1)
    run_analysis(sys.argv[1], sys.argv[2])
