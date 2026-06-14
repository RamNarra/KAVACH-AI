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

def run_analysis(apk_path: str, output_path: str):
    findings = {
        "suspicious_strings": [],
        "dangerous_api_chains": [],
        "risky_classes": [],
        "score": 0,
    }

    try:
        a = APK(apk_path)
        findings["package_name"] = a.get_package() or ""
        findings["launcher_activity"] = a.get_main_activity() or ""
        try:
            import xml.etree.ElementTree as ET
            manifest_xml = a.get_android_manifest_xml()
            findings["manifest_content"] = ET.tostring(manifest_xml, encoding="utf-8").decode("utf-8") if manifest_xml is not None else ""
        except Exception:
            findings["manifest_content"] = ""

        d_list = []
        for dex in a.get_all_dex():
            df = DalvikVMFormat(dex)
            d_list.append(df)
        # NOTE: We intentionally skip Analysis() / dx.create_xref() — those cost 12-16s
        # We operate directly on DalvikVMFormat (ClassDefItem / EncodedMethod) which is
        # fully sufficient for string scanning, taint tracking and superclass inspection.
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

    # 2. Register-level Data-Flow Taint Tracking & Inter-procedural Propagation
    def parse_descriptor_reg_size(descriptor: str) -> int:
        if not descriptor or '(' not in descriptor or ')' not in descriptor:
            return 0
        params_part = descriptor.split('(')[1].split(')')[0]
        size = 0
        i = 0
        while i < len(params_part):
            char = params_part[i]
            if char == 'L':
                end = params_part.find(';', i)
                i = end + 1 if end != -1 else i + 1
                size += 1
            elif char == '[':
                i += 1
                while i < len(params_part) and params_part[i] == '[':
                    i += 1
                if i < len(params_part):
                    el_char = params_part[i]
                    if el_char == 'L':
                        end = params_part.find(';', i)
                        i = end + 1 if end != -1 else i + 1
                    else:
                        i += 1
                size += 1
            elif char in ('J', 'D'):
                size += 2
                i += 1
            elif char in ('Z', 'B', 'S', 'C', 'I', 'F'):
                size += 1
                i += 1
            else:
                i += 1
        return size

    def analyze_method_taint(method, instructions, returns_taint_methods, exfiltrates_param_methods):
        """Accepts an EncodedMethod directly (from DalvikVMFormat.get_classes())."""
        if not method:
            return False, set(), []
        code = method.get_code()
        if not code:
            return False, set(), []

        descriptor = str(method.get_descriptor() or "")
        access_flags = str(method.get_access_flags_string() or "")
        is_static = 'static' in access_flags
        this_reg_size = 0 if is_static else 1
        param_regs_size = parse_descriptor_reg_size(descriptor)
        total_param_regs = this_reg_size + param_regs_size
        reg_size = code.get_registers_size()

        param_to_reg = {}
        for idx in range(total_param_regs):
            reg_num = reg_size - total_param_regs + idx
            param_to_reg[idx] = f"v{reg_num}"

        tainted_regs = {}
        for idx, reg in param_to_reg.items():
            tainted_regs[reg] = {f"param_{idx}"}

        detected_flows = []
        returns_taint = False

        if not instructions:
            try:
                if hasattr(code, "get_bc"):
                    instructions = list(code.get_bc().get_instructions())
                elif hasattr(code, "get_instructions"):
                    instructions = list(code.get_instructions())
                else:
                    instructions = list(code)
            except Exception:
                return False, set(), []

        if len(instructions) > 1500:
            instructions = instructions[:1500]

        for idx, inst in enumerate(instructions):
            try:
                name = str(inst.get_name() or "")
                output = str(inst.get_output() or "")
            except Exception:
                continue

            is_invoke = "invoke-" in name
            called_method = None
            if is_invoke:
                match = re.search(r"->([a-zA-Z0-9_]+)\(", output)
                if match:
                    called_method = match.group(1)

            is_source = False
            source_label = None
            if called_method:
                for src_api, _, label, _ in _DANGEROUS_API_CHAINS:
                    if called_method == src_api:
                        is_source = True
                        source_label = src_api
                        break
                
                # Check if called method is known to return taint from previous pass
                full_method_id = f"{output.split('->')[-1].split('(')[0]}" if '->' in output else called_method
                if full_method_id in returns_taint_methods:
                    is_source = True
                    source_label = f"method_{full_method_id}"

            if is_invoke and is_source:
                if idx + 1 < len(instructions):
                    next_inst = instructions[idx + 1]
                    try:
                        next_name = str(next_inst.get_name() or "")
                        next_output = str(next_inst.get_output() or "")
                    except Exception:
                        continue
                    if "move-result" in next_name:
                        dest_reg_match = re.match(r"^(v\d+)", next_output.strip())
                        if dest_reg_match:
                            dest_reg = dest_reg_match.group(1)
                            tainted_regs[dest_reg] = {source_label}
                continue

            # Handle moves
            is_move = name.startswith("move") and "result" not in name and "exception" not in name
            if is_move:
                regs = re.findall(r"v\d+", output)
                if len(regs) >= 2:
                    dest_reg, src_reg = regs[0], regs[1]
                    if src_reg in tainted_regs:
                        tainted_regs[dest_reg] = set(tainted_regs[src_reg])
                    elif dest_reg in tainted_regs:
                        del tainted_regs[dest_reg]
                continue

            # Handle sinks & parameter exfiltrations
            if is_invoke and called_method:
                invoked_regs = []
                if "range" in name:
                    range_match = re.search(r"\{(v\d+)\s*\.\.\s*(v\d+)\}", output)
                    if range_match:
                        start_v, end_v = range_match.group(1), range_match.group(2)
                        try:
                            start_num = int(start_v[1:])
                            end_num = int(end_v[1:])
                            for r_num in range(start_num, end_num + 1):
                                invoked_regs.append(f"v{r_num}")
                        except Exception:
                            pass
                else:
                    braces_match = re.search(r"\{([^}]+)\}", output)
                    if braces_match:
                        invoked_regs = re.findall(r"v\d+", braces_match.group(1))
                    else:
                        prefix = output.split('L')[0] if 'L' in output else output
                        invoked_regs = re.findall(r"v\d+", prefix)

                tainted_inputs = []
                for reg in invoked_regs:
                    if reg in tainted_regs:
                        tainted_inputs.extend(list(tainted_regs[reg]))

                if tainted_inputs:
                    is_sink = False
                    sink_label = None
                    for _, sink_api, label, _ in _DANGEROUS_API_CHAINS:
                        if called_method == sink_api:
                            is_sink = True
                            sink_label = label
                            break

                    if is_sink:
                        for taint_source in tainted_inputs:
                            detected_flows.append({
                                "source": taint_source,
                                "sink": called_method,
                                "label": sink_label
                            })
                    else:
                        # Inter-procedural flow via parameters
                        full_method_id = f"{output.split('->')[-1].split('(')[0]}" if '->' in output else called_method
                        if full_method_id in exfiltrates_param_methods:
                            exfil_indices = exfiltrates_param_methods[full_method_id]
                            for ex_idx in exfil_indices:
                                if ex_idx < len(invoked_regs):
                                    reg = invoked_regs[ex_idx]
                                    if reg in tainted_regs:
                                        for taint_source in tainted_regs[reg]:
                                            detected_flows.append({
                                                "source": taint_source,
                                                "sink": called_method,
                                                "label": f"Interprocedural flow via {full_method_id}"
                                            })

            # Handle returns
            if name.startswith("return") and name != "return-void":
                ret_reg_match = re.search(r"(v\d+)", output)
                if ret_reg_match:
                    ret_reg = ret_reg_match.group(1)
                    if ret_reg in tainted_regs:
                        for taint_source in tainted_regs[ret_reg]:
                            if not taint_source.startswith("param_"):
                                returns_taint = True

        exfiltrates_params = set()
        for flow in detected_flows:
            if flow["source"].startswith("param_"):
                try:
                    param_idx = int(flow["source"].split("_")[1])
                    exfiltrates_params.add(param_idx)
                except Exception:
                    pass

        api_chain_flows = [f for f in detected_flows if not f["source"].startswith("param_")]
        return returns_taint, exfiltrates_params, api_chain_flows

    try:
        returns_taint_methods = set()
        exfiltrates_param_methods = {}
        
        total_dex_size = sum(len(dex) for dex in a.get_all_dex())
        skip_taint = total_dex_size > 15 * 1024 * 1024
        
        if not skip_taint:
            _ALL_TARGET_APIS = set()
            for src_api, sink_api, _, _ in _DANGEROUS_API_CHAINS:
                _ALL_TARGET_APIS.add(src_api)
                _ALL_TARGET_APIS.add(sink_api)
                
            _PRUNED_LIBS = {
                "androidx", "android.support", "kotlin", "kotlinx", "okio", "okhttp3", 
                "retrofit2", "reactivex", "squareup", "fasterxml", "intellij", "jetbrains",
                "com.google", "google.protobuf", "com.google.android", "com.google.firebase",
                "com.adjust", "com.facebook", "com.unity3d", "com.appsflyer", "com.flurry",
                "com.mixpanel", "com.segment", "io.fabric", "com.crashlytics", "org.json",
                "org.jsoup", "com.google.gson", "org.yaml", "com.amazonaws", "com.microsoft",
                "org.apache", "io.reactivex", "com.github", "org.bouncycastle", "com.fasterxml",
                "org.w3c", "org.xml", "dom4j", "jaxen", "com.ta.utdid2", "com.ut.device",
                "com.alibaba", "com.tencent", "com.baidu", "com.alipay", "com.xiaomi",
                "com.huawei", "com.oppo", "com.vivo", "com.meizu"
            }
            
            active_methods = []
            app_pkg = (a.get_package() or "").strip()
            for d in d_list:
                for cls in d.get_classes():
                    class_name = str(cls.name or "")
                    cleaned_cls = class_name.replace("/", ".").strip("L;")
                    is_lib = False
                    for p in _PRUNED_LIBS:
                        if cleaned_cls.startswith(p):
                            # Never prune if it starts with the application package name
                            if app_pkg and cleaned_cls.startswith(app_pkg):
                                is_lib = False
                                break
                            is_lib = True
                            break
                    if is_lib:
                        # Fast pre-check: only prune library class if it does not reference any target APIs
                        has_target_api = False
                        for m in cls.get_methods():
                            code = m.get_code()
                            if not code:
                                continue
                            try:
                                if hasattr(code, "get_bc"):
                                    insts = code.get_bc().get_instructions()
                                elif hasattr(code, "get_instructions"):
                                    insts = code.get_instructions()
                                else:
                                    insts = code
                                for inst in insts:
                                    output = str(inst.get_output() or "")
                                    if any(target in output for target in _ALL_TARGET_APIS):
                                        has_target_api = True
                                        break
                            except Exception:
                                pass
                            if has_target_api:
                                break
                        if not has_target_api:
                            continue

                    c_name_str = class_name.replace("/", ".").strip("L;")

                    for m in cls.get_methods():
                        code = m.get_code()
                        if not code:
                            continue
                        
                        try:
                            if hasattr(code, "get_bc"):
                                insts = list(code.get_bc().get_instructions())
                            elif hasattr(code, "get_instructions"):
                                insts = list(code.get_instructions())
                            else:
                                insts = list(code)
                        except Exception:
                            continue
                            
                        if not insts:
                            continue
                            
                        if len(insts) > 1500:
                            insts = insts[:1500]
                            
                        invoked_methods = set()
                        has_invoke = False
                        for inst in insts:
                            try:
                                name = str(inst.get_name() or "")
                                if "invoke-" in name:
                                    has_invoke = True
                                    output = str(inst.get_output() or "")
                                    match = re.search(r"->([a-zA-Z0-9_]+)\(", output)
                                    if match:
                                        invoked_methods.add(match.group(1))
                            except Exception:
                                continue
                                
                        if not has_invoke:
                            continue
                            
                        active_methods.append({
                            "method": m,
                            "instructions": insts,
                            "invoked_methods": invoked_methods,
                            "class_name": c_name_str,
                            "name": str(m.name or "")
                        })

            # Cap active methods to prevent timeouts on huge DEXes
            MAX_ACTIVE_METHODS = 2500
            if len(active_methods) > MAX_ACTIVE_METHODS:
                active_methods.sort(key=lambda x: len(x["invoked_methods"] & _ALL_TARGET_APIS), reverse=True)
                active_methods = active_methods[:MAX_ACTIVE_METHODS]

            # First pass: identify methods returning taint or exfiltrating parameters
            for m_data in active_methods:
                if not (m_data["invoked_methods"] & _ALL_TARGET_APIS):
                    continue
                try:
                    ret_taint, exfil_params, _ = analyze_method_taint(
                        m_data["method"], 
                        m_data["instructions"], 
                        set(), 
                        {}
                    )
                    if ret_taint:
                        returns_taint_methods.add(m_data["name"])
                    if exfil_params:
                        exfiltrates_param_methods[m_data["name"]] = exfil_params
                except Exception:
                    pass

            # Second pass: trace final flows
            final_flows = []
            second_pass_targets = _ALL_TARGET_APIS | returns_taint_methods | set(exfiltrates_param_methods.keys())
            for m_data in active_methods:
                if not (m_data["invoked_methods"] & second_pass_targets):
                    continue
                try:
                    _, _, api_flows = analyze_method_taint(
                        m_data["method"], 
                        m_data["instructions"], 
                        returns_taint_methods, 
                        exfiltrates_param_methods
                    )
                    if api_flows:
                        for flow in api_flows:
                            final_flows.append({
                                "class_name": m_data["class_name"],
                                "source": flow["source"],
                                "sink": flow["sink"],
                                "label": flow["label"]
                            })
                except Exception:
                    pass

            matched_chains = set()
            for flow in final_flows:
                chain_key = f"{flow['source']}:{flow['sink']}"
                if chain_key not in matched_chains:
                    matched_chains.add(chain_key)
                    
                    score = 20
                    for read_api, write_api, label, sc in _DANGEROUS_API_CHAINS:
                        if (flow["source"] == read_api or flow["source"].endswith(read_api)) and flow["sink"] == write_api:
                            score = sc
                            break
                            
                    findings["dangerous_api_chains"].append({
                        "type": flow["label"],
                        "risk_score": score,
                        "severity": "CRITICAL" if score >= 25 else "HIGH",
                        "description": f"Verified register taint flow in {flow['class_name']}: {flow['source']} → {flow['sink']} ({flow['label']})"
                    })
                    findings["score"] += score
        else:
            print(f"Skipping taint analysis: DEX size {total_dex_size / 1024 / 1024:.2f} MB is > 15 MB limit.")

    except Exception as exc:
        print(f"Error in bytecode register taint propagation audit: {exc}")

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

    # 4. Advanced Behavioral Signatures
    findings["behavioral_signatures"] = []
    
    # Check for Dynamic Dex/Jar loading
    has_dynamic_loading = False
    for d in d_list:
        for val_raw in d.get_strings():
            if isinstance(val_raw, bytes):
                val = val_raw.decode('utf-8', errors='ignore')
            else:
                val = str(val_raw)
            if "DexClassLoader" in val or "PathClassLoader" in val:
                has_dynamic_loading = True
                break
        if has_dynamic_loading:
            break
            
    if has_dynamic_loading:
        findings["behavioral_signatures"].append({
            "type": "Dynamic Class Loading Detected",
            "risk_score": 25,
            "severity": "HIGH",
            "description": "App references DexClassLoader or PathClassLoader, which allows loading external bytecode at runtime (evasion technique)."
        })
        findings["score"] += 25

    # Check for System Overlay usage
    has_overlay_reference = False
    for d in d_list:
        for val_raw in d.get_strings():
            if isinstance(val_raw, bytes):
                val = val_raw.decode('utf-8', errors='ignore')
            else:
                val = str(val_raw)
            if "TYPE_APPLICATION_OVERLAY" in val or "TYPE_SYSTEM_ALERT_WINDOW" in val or "system_alert_window" in val:
                has_overlay_reference = True
                break
        if has_overlay_reference:
            break
            
    if has_overlay_reference:
        findings["behavioral_signatures"].append({
            "type": "System Overlay Creation API",
            "risk_score": 30,
            "severity": "CRITICAL",
            "description": "App references WindowManager Overlay constants (used by banking trojans for overlay phishing screens)."
        })
        findings["score"] += 30

    # Check for SMS Interception receiver intent
    has_sms_receiver_intent = False
    if findings.get("manifest_content"):
        manifest_str = findings["manifest_content"]
        if "SMS_RECEIVED" in manifest_str or "RECEIVE_SMS" in manifest_str:
            has_sms_receiver_intent = True
            
    if has_sms_receiver_intent:
        findings["behavioral_signatures"].append({
            "type": "SMS Interception Receiver",
            "risk_score": 35,
            "severity": "CRITICAL",
            "description": "App declares an intent receiver or permission for SMS_RECEIVED (used to intercept banking OTPs)."
        })
        findings["score"] += 35

    with open(output_path, "w") as f:
        json.dump(findings, f)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: androguard_analyzer.py <apk_path> <output_json_path>")
        sys.exit(1)
    run_analysis(sys.argv[1], sys.argv[2])
