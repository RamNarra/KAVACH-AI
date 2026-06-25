"""
anti_evasion.py — Sandbox-evasion telemetry detector.
"""
from typing import Dict, List, Any

def detect_evasion_behaviors(normalized_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Scans the dynamic trace stream for category markers signifying VM/Debugger/Root 
    evasion behaviors or timing attacks, and returns a penalty report.
    """
    evidence = []
    has_vm_checks = False
    has_timing_attacks = False
    has_root_checks = False
    has_battery_checks = False

    for event in normalized_events:
        category = event.get("category", "")
        action = event.get("action", "")
        ev = event.get("evidence", "")

        # 1. VM/Emulator checks
        if category == "anti_vm.signal":
            has_vm_checks = True
            if "property_check" in action:
                evidence.append(f"Queried sandbox property: {ev}")
            else:
                evidence.append(f"Checked for VM-specific artifact paths: {ev}")

        # 2. Timing/Stalling checks
        elif category == "anti_analysis.timing":
            has_timing_attacks = True
            evidence.append(f"Attempted execution stall: {ev}")

        # 3. Root/Instrumentation checks
        elif category in ("anti_root.signal", "anti_hook.signal", "anti_debug.signal"):
            has_root_checks = True
            evidence.append(f"Checked for analysis tools (su, Frida, debugger): {ev}")

        # 4. Battery state checks
        elif category == "anti_analysis.battery":
            has_battery_checks = True
            evidence.append(f"Queried battery details: {ev}")

    # Deduplicate evidence
    evidence = list(set(evidence))

    is_evading = has_vm_checks or has_timing_attacks or has_root_checks or has_battery_checks
    
    return {
        "evasion_detected": is_evading,
        "evasion_score_boost": 20 if is_evading else 0,
        "evidence_highlights": evidence[:5],
        "categories_triggered": {
            "vm": has_vm_checks,
            "timing": has_timing_attacks,
            "root_frida": has_root_checks,
            "battery": has_battery_checks
        }
    }

def detect_static_evasion_behaviors(evidence_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Scans static analysis findings (manifest, decompiler outputs, APKId flags, Quark rules, suspicious strings)
    for signature matches indicative of sandbox evasion.
    """
    evidence = []
    has_vm_checks = False
    has_timing_attacks = False
    has_root_checks = False
    has_battery_checks = False

    # 1. Check permissions (battery optimization ignore or debugger attachments)
    permissions = [p.get("name", "") for p in evidence_dict.get("permissions", [])]
    if "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" in permissions:
        has_battery_checks = True
        evidence.append("Requested battery optimization ignore (anti-idle check)")

    # 2. Check APKId and Quark rule hits
    for hit in evidence_dict.get("malware_rule_hits", []):
        rule = str(hit.get("rule", "")).lower()
        desc = str(hit.get("description", "")).lower()
        
        if "anti_vm" in rule or "anti-vm" in desc or "emulator" in desc or "virtualbox" in desc or "qemu" in desc:
            has_vm_checks = True
            evidence.append(f"Static rule matched VM detection: {hit.get('description')}")
        if "anti_debug" in rule or "debugger" in desc or "tracerpid" in desc:
            has_root_checks = True
            evidence.append(f"Static rule matched debugger evasion: {hit.get('description')}")
        if "anti_sharing" in rule or "sleep" in desc or "delay" in desc:
            has_timing_attacks = True
            evidence.append(f"Static rule matched timing delay: {hit.get('description')}")

    # 2b. Check YARA matches
    for m in evidence_dict.get("yara_matches", []):
        rule = str(m.get("rule_name", "")).lower()
        meta = m.get("meta", {})
        desc = str(meta.get("description", "")).lower()
        
        if "evasion" in rule or "vm" in rule or "emulator" in desc or "qemu" in desc:
            has_vm_checks = True
            evidence.append(f"YARA matched VM evasion: {meta.get('description', 'VM detection signature')}")
        if "debug" in rule or "debugger" in desc:
            has_root_checks = True
            evidence.append(f"YARA matched debugger evasion: {meta.get('description', 'Debugger detection signature')}")

    # 3. Check for specific anti-VM and anti-analysis strings in JADX / decompiled output
    # Flattening data keys to scan strings
    flat_strings = []
    for cat in ["network_indicators", "crypto_issues", "hardcoded_secrets", "suspicious_urls", "reflection_dynamic_loading", "obfuscation_signals"]:
        for item in evidence_dict.get(cat, []):
            desc = str(item.get("description", "")).lower()
            val = str(item.get("value", "")).lower()
            flat_strings.append(desc)
            flat_strings.append(val)

    vm_keywords = ["ro.kernel.qemu", "ro.hardware", "ro.product.model", "ro.product.manufacturer", "init.svc.goldfish-logcat", "qemu_pipe", "qemud"]
    root_keywords = ["frida-server", "re.frida.server", "supersu", "magisk", "su.d", "su-c"]
    timing_keywords = ["thread.sleep", "systemclock.sleep"]

    for s in flat_strings:
        if any(kw in s for kw in vm_keywords):
            has_vm_checks = True
            evidence.append(f"Hardcoded VM verification string reference: {s[:60]}")
        if any(kw in s for kw in root_keywords):
            has_root_checks = True
            evidence.append(f"Hardcoded Root/Frida tool reference: {s[:60]}")
        if any(kw in s for kw in timing_keywords):
            has_timing_attacks = True
            evidence.append(f"Hardcoded execution stall reference: {s[:60]}")

    # Deduplicate evidence
    evidence = list(set(evidence))
    is_evading = has_vm_checks or has_timing_attacks or has_root_checks or has_battery_checks

    return {
        "evasion_detected": is_evading,
        "evasion_score_boost": 20 if is_evading else 0,
        "evidence_highlights": evidence[:5],
        "categories_triggered": {
            "vm": has_vm_checks,
            "timing": has_timing_attacks,
            "root_frida": has_root_checks,
            "battery": has_battery_checks
        }
    }

def merge_evasion_reports(static_rep: Dict[str, Any], dynamic_rep: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Combines the results of static and dynamic evasion sweeps into a single unified evasion report.
    """
    if not dynamic_rep:
        return static_rep
        
    s_detected = static_rep.get("evasion_detected", False)
    d_detected = dynamic_rep.get("evasion_detected", False)
    is_evading = s_detected or d_detected
    
    highlights = list(set(static_rep.get("evidence_highlights", []) + dynamic_rep.get("evidence_highlights", [])))
    
    categories = {}
    for cat in ["vm", "timing", "root_frida", "battery"]:
        categories[cat] = static_rep.get("categories_triggered", {}).get(cat, False) or \
                           dynamic_rep.get("categories_triggered", {}).get(cat, False)
                           
    return {
        "evasion_detected": is_evading,
        "evasion_score_boost": 20 if is_evading else 0,
        "evidence_highlights": highlights[:5],
        "categories_triggered": categories
    }
