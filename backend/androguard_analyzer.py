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
        from androguard.core.analysis.analysis import Analysis
        a = APK(apk_path)
        d_list = []
        dx = Analysis()
        for dex in a.get_all_dex():
            df = DalvikVMFormat(dex)
            d_list.append(df)
            dx.add(df)
        dx.create_xref()
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

    def analyze_method_taint(m_anal, returns_taint_methods, exfiltrates_param_methods):
        method = m_anal.get_method()
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

        try:
            instructions = list(code.get_instructions())
        except Exception:
            return False, set(), []

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
        
        all_methods = []
        for c_anal in dx.get_classes():
            if c_anal.is_external():
                continue
            for m_anal in c_anal.get_methods():
                if m_anal.is_external():
                    continue
                all_methods.append(m_anal)

        for m_anal in all_methods:
            try:
                ret_taint, exfil_params, _ = analyze_method_taint(m_anal, set(), {})
                method = m_anal.get_method()
                if method:
                    m_name = str(method.name or "")
                    if ret_taint:
                        returns_taint_methods.add(m_name)
                    if exfil_params:
                        exfiltrates_param_methods[m_name] = exfil_params
            except Exception:
                pass

        final_flows = []
        for m_anal in all_methods:
            try:
                _, _, api_flows = analyze_method_taint(m_anal, returns_taint_methods, exfiltrates_param_methods)
                if api_flows:
                    c_name = m_anal.class_name
                    if isinstance(c_name, bytes):
                        c_name = c_name.decode('utf-8', errors='ignore')
                    c_name = str(c_name or "").replace("/", ".").strip("L;")
                    for flow in api_flows:
                        final_flows.append({
                            "class_name": c_name,
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

    with open(output_path, "w") as f:
        json.dump(findings, f)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: androguard_analyzer.py <apk_path> <output_json_path>")
        sys.exit(1)
    run_analysis(sys.argv[1], sys.argv[2])
