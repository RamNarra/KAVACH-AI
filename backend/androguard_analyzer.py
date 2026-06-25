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

def disassemble_class_to_smali(cls) -> str:
    """Disassemble an Androguard class definition to Smali formatting."""
    lines = []
    class_name = str(cls.name or "").replace("/", ".").strip("L;")
    try:
        sup_name = str(cls.get_superclassname() or "").replace("/", ".").strip("L;")
    except Exception:
        sup_name = "java.lang.Object"
    lines.append(f".class public L{class_name};")
    lines.append(f".super L{sup_name};")
    lines.append("")
    
    for m in cls.get_methods():
        m_name = str(m.name or "")
        m_desc = str(m.get_descriptor() or "")
        try:
            m_flags = str(m.get_access_flags_string() or "")
        except Exception:
            m_flags = "public"
        lines.append(f".method {m_flags} {m_name}{m_desc}")
        
        code = m.get_code()
        if code:
            try:
                lines.append(f"    .registers {code.get_registers_size()}")
            except Exception:
                pass
            try:
                if hasattr(code, "get_bc"):
                    insts = code.get_bc().get_instructions()
                elif hasattr(code, "get_instructions"):
                    insts = code.get_instructions()
                else:
                    insts = code
                for inst in insts:
                    inst_name = str(inst.get_name() or "")
                    inst_out = str(inst.get_output() or "")
                    lines.append(f"    {inst_name} {inst_out}")
            except Exception as e:
                lines.append(f"    # Disassembly error: {e}")
        lines.append(".end method")
        lines.append("")
    return "\n".join(lines)

def score_and_select_classes_smali(d_list, dangerous_api_chains, package_name):
    """Identify top 8 suspicious classes and disassemble them to Smali."""
    class_scores = {}
    class_objects = {}
    
    # Pruned third party frameworks to avoid disassembling standard code
    _PRUNED_LIBS = {
        "androidx", "android.support", "kotlin", "kotlinx", "okio", "okhttp3", 
        "retrofit2", "reactivex", "squareup", "fasterxml", "intellij", "jetbrains",
        "com.google", "google.protobuf", "com.google.android", "com.google.firebase",
        "com.adjust", "com.facebook", "com.unity3d", "com.appsflyer", "com.flurry",
        "com.mixpanel", "com.segment", "io.fabric", "com.crashlytics", "org.json",
        "org.jsoup", "com.google.gson", "org.yaml", "com.amazonaws", "com.microsoft",
        "org.apache", "io.reactivex", "com.github", "org.bouncycastle", "com.fasterxml",
        "org.w3c", "org.xml", "dom4j", "jaxen"
    }

    for d in d_list:
        try:
            for cls in d.get_classes():
                cls_name_raw = cls.name
                if isinstance(cls_name_raw, bytes):
                    cls_name = cls_name_raw.decode('utf-8', errors='ignore')
                else:
                    cls_name = str(cls_name_raw or "")
                cls_name_norm = cls_name.replace("/", ".").strip("L;")
                
                is_lib = False
                for ns in _PRUNED_LIBS:
                    if cls_name_norm.startswith(ns):
                        if package_name and cls_name_norm.startswith(package_name):
                            is_lib = False
                            break
                        is_lib = True
                        break
                if is_lib:
                    continue
                    
                score = 0
                try:
                    sup_raw = cls.get_superclassname()
                    sup = sup_raw.decode('utf-8', errors='ignore') if isinstance(sup_raw, bytes) else str(sup_raw or "")
                except Exception:
                    sup = ""
                
                # Check Superclasses
                for risky_cls, _, sc in _RISKY_SUPERCLASSES:
                    if risky_cls in sup:
                        score += 40
                        break
                        
                # Check instructions content
                src_str = ""
                for m in cls.get_methods():
                    code = m.get_code()
                    if code:
                        try:
                            if hasattr(code, "get_bc"):
                                insts = code.get_bc().get_instructions()
                            elif hasattr(code, "get_instructions"):
                                insts = code.get_instructions()
                            else:
                                insts = code
                            for inst in insts:
                                src_str += " " + str(inst.get_output() or "")
                        except Exception:
                            pass
                src_str = src_str.lower()
                
                if any(api in src_str for api in ('content://sms', 'receivesms', 'readsms', 'sendsms', 'smsmanager')):
                    score += 30
                if any(api in src_str for api in ('type_application_overlay', 'system_alert_window', 'addview', 'windowmanager')):
                    score += 30
                if 'onaccessibilityevent' in src_str:
                    score += 25
                if 'dexclassloader' in src_str or 'pathclassloader' in src_str:
                    score += 20
                if any(api in src_str for api in ('class.forname', 'getdeclaredmethod', 'invoke(')):
                    score += 15
                    
                if score > 0:
                    class_scores[cls_name_norm] = score
                    class_objects[cls_name_norm] = cls
        except Exception:
            pass
            
    for chain in dangerous_api_chains:
        cls_name = chain.get("class_name")
        if cls_name and cls_name in class_objects:
            class_scores[cls_name] = class_scores.get(cls_name, 0) + 30
            
    sorted_classes = sorted(class_scores.items(), key=lambda x: x[1], reverse=True)
    smali_sources = {}
    for cls_name, _ in sorted_classes[:8]:
        cls = class_objects[cls_name]
        try:
            smali_sources[cls_name.replace(".", "/") + ".smali"] = disassemble_class_to_smali(cls)
        except Exception as e:
            print(f"Error disassembling {cls_name}: {e}")
            
    return smali_sources

def extract_certificate_info(a):
    """
    Extracts X.509 certificate metadata using Androguard's APK API.
    """
    cert_info = {
        "is_signed": False,
        "subject": "",
        "issuer": "",
        "valid_from": "",
        "valid_to": "",
        "sha256": "",
        "sha1": "",
        "serial_number": "",
        "signature_algo": "",
        "signature_scheme": ""
    }
    try:
        if not a.is_signed():
            return cert_info
        
        cert_info["is_signed"] = True
        
        # Get signature scheme names (e.g., v1, v2, v3)
        try:
            signature_names = a.get_signature_names()
            cert_info["signature_scheme"] = ", ".join(signature_names) if signature_names else "v1"
        except Exception:
            cert_info["signature_scheme"] = "v1"
            
        certs = a.get_certificates()
        if not certs:
            return cert_info
            
        # Extract metadata from the first certificate in the chain
        cert = certs[0]
        
        # Helper to format Name objects to standard DN format
        def format_dn(dn_obj):
            if not dn_obj:
                return ""
            try:
                native = dn_obj.native
                mapping = {
                    "common_name": "CN",
                    "organization_name": "O",
                    "organizational_unit_name": "OU",
                    "country_name": "C",
                    "locality_name": "L",
                    "state_or_province_name": "ST",
                    "email_address": "emailAddress"
                }
                dn_parts = []
                for k, v in native.items():
                    label = mapping.get(k, k.upper())
                    if isinstance(v, list):
                        for sub_v in v:
                            dn_parts.append(f"{label}={sub_v}")
                    else:
                        dn_parts.append(f"{label}={v}")
                return ", ".join(dn_parts)
            except Exception:
                return str(dn_obj)

        cert_info["subject"] = format_dn(cert.subject)
        cert_info["issuer"] = format_dn(cert.issuer)
        
        # Get fingerprints
        try:
            # cert.sha256 returns bytes in asn1crypto
            sha256_bytes = cert.sha256
            cert_info["sha256"] = ":".join(f"{b:02X}" for b in sha256_bytes)
        except Exception:
            pass
            
        try:
            sha1_bytes = cert.sha1
            cert_info["sha1"] = ":".join(f"{b:02X}" for b in sha1_bytes)
        except Exception:
            pass
            
        # Get validity dates
        try:
            validity = cert.native.get('tbs_certificate', {}).get('validity', {})
            not_before = validity.get('not_before')
            not_after = validity.get('not_after')
            if not_before:
                cert_info["valid_from"] = not_before.isoformat() if hasattr(not_before, 'isoformat') else str(not_before)
            if not_after:
                cert_info["valid_to"] = not_after.isoformat() if hasattr(not_after, 'isoformat') else str(not_after)
        except Exception:
            pass
            
        # Get serial number
        try:
            serial_num = cert.serial_number
            if isinstance(serial_num, int):
                cert_info["serial_number"] = hex(serial_num).upper().replace("0X", "")
            else:
                cert_info["serial_number"] = str(serial_num)
        except Exception:
            pass
            
        # Get signature algorithm
        try:
            sig_algo = cert.signature_algorithm
            if sig_algo and hasattr(sig_algo, 'native') and 'algorithm' in sig_algo.native:
                cert_info["signature_algo"] = sig_algo.native['algorithm']
            else:
                cert_info["signature_algo"] = str(sig_algo)
        except Exception:
            pass
            
    except Exception as e:
        print(f"Error extracting certificate info: {e}")
        
    return cert_info

def generate_call_graph_data(d_list, findings):
    import re
    # 1. Map of classes to superclasses
    class_supers = {}
    for d in d_list:
        try:
            for cls in d.get_classes():
                cls_name_raw = cls.name
                cls_name = cls_name_raw.decode('utf-8', errors='ignore') if isinstance(cls_name_raw, bytes) else str(cls_name_raw or "")
                
                try:
                    sup_raw = cls.get_superclassname()
                    sup = sup_raw.decode('utf-8', errors='ignore') if isinstance(sup_raw, bytes) else str(sup_raw or "")
                    class_supers[cls_name] = sup
                except Exception:
                    class_supers[cls_name] = "java.lang.Object"
        except Exception:
            pass

    # 2. Extract manifest components if available
    manifest_components = set()
    try:
        if findings.get("manifest_content"):
            import xml.etree.ElementTree as ET
            manifest_xml = ET.fromstring(findings["manifest_content"])
            ns = "{http://schemas.android.com/apk/res/android}"
            name_attr = f"{ns}name"
            for tag in ["activity", "service", "receiver", "provider", "application"]:
                for elem in manifest_xml.iter(tag):
                    name = elem.attrib.get(name_attr)
                    if name:
                        # Normalize format to Lpackage/Class;
                        if name.startswith("."):
                            pkg = findings.get("package_name", "")
                            name = pkg + name
                        name_norm = "L" + name.replace(".", "/") + ";"
                        manifest_components.add(name_norm)
    except Exception as e:
        print(f"Error parsing manifest components: {e}")

    # 3. Define Sources & Sinks lists
    SOURCES_LIST = {
        "getDeviceId": "telephony",
        "getSubscriberId": "telephony",
        "getLine1Number": "telephony",
        "getSimSerialNumber": "telephony",
        "getImei": "telephony",
        "getMeid": "telephony",
        "getAccounts": "accounts",
        "getAccountsByType": "accounts",
        "getLastKnownLocation": "location",
        "requestLocationUpdates": "location",
        "getMessageBody": "sms",
        "getOriginatingAddress": "sms",
        "onAccessibilityEvent": "accessibility",
        "onBind": "lifecycle"
    }

    SINKS_LIST = {
        "sendTextMessage": "sms-send",
        "sendMultipartTextMessage": "sms-send",
        "openConnection": "network",
        "connect": "network",
        "execute": "network",
        "enqueue": "network",
        "evaluateJavascript": "webview",
        "performGlobalAction": "accessibility-inject",
        "addView": "overlay",
        "exec": "exec",
        "loadLibrary": "exec"
    }

    # 4. Build adjacency list from code instructions
    adj = {} # caller_id -> set of callee_ids
    node_metadata = {} # node_id -> dict of properties
    
    # Helper to check if class is a system/library class
    _PRUNED_LIBS = [
        "Landroidx/", "Landroid/support/", "Lkotlin/", "Lkotlinx/", "Lokio/", "Lokhttp3/", 
        "Lretrofit2/", "Lcom/google/", "Lorg/json/", "Lorg/apache/", "Ljava/", "Landroid/arch/"
    ]
    
    def is_library_class(cname):
        for lib in _PRUNED_LIBS:
            if cname.startswith(lib):
                # Don't prune if it matches package name
                pkg_prefix = "L" + (findings.get("package_name") or "").replace(".", "/")
                if pkg_prefix and cname.startswith(pkg_prefix):
                    return False
                return True
        return False

    # Collect all internal methods to know what is defined inside the APK
    internal_methods = set()
    for d in d_list:
        try:
            for cls in d.get_classes():
                cls_name_raw = cls.name
                cls_name = cls_name_raw.decode('utf-8', errors='ignore') if isinstance(cls_name_raw, bytes) else str(cls_name_raw or "")
                for m in cls.get_methods():
                    m_id = f"{cls_name}->{m.name}{m.get_descriptor()}"
                    internal_methods.add(m_id)
        except Exception:
            pass

    # Walk through classes and scan instructions to build edges
    for d in d_list:
        try:
            for cls in d.get_classes():
                cls_name_raw = cls.name
                cls_name = cls_name_raw.decode('utf-8', errors='ignore') if isinstance(cls_name_raw, bytes) else str(cls_name_raw or "")
                
                # We skip library classes for callgraph unless they are explicitly referenced
                if is_library_class(cls_name):
                    continue
                    
                # Class category classification
                is_entrypoint_class = cls_name in manifest_components or cls_name.replace("/", ".").strip("L;") == findings.get("launcher_activity")
                sup = class_supers.get(cls_name, "")
                is_accessibility_class = "AccessibilityService" in sup
                is_receiver_class = "DeviceAdminReceiver" in sup or "BroadcastReceiver" in sup
                
                for m in cls.get_methods():
                    caller_id = f"{cls_name}->{m.name}{m.get_descriptor()}"
                    
                    # Classify caller node
                    node_type = "method"
                    tags = []
                    if is_entrypoint_class and m.name in ["onCreate", "onStartCommand", "onReceive", "onStart", "onResume", "onAccessibilityEvent"]:
                        node_type = "entrypoint"
                        tags.append("lifecycle")
                        if is_accessibility_class:
                            tags.append("accessibility")
                        if is_receiver_class:
                            tags.append("receiver")
                    elif m.name == "onAccessibilityEvent":
                        node_type = "entrypoint"
                        tags.append("accessibility")
                        
                    node_metadata[caller_id] = {
                        "class": cls_name,
                        "method": m.name,
                        "type": node_type,
                        "tags": tags,
                        "risk": "benign"
                    }

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
                            try:
                                name = str(inst.get_name() or "")
                                if "invoke-" in name:
                                    output = str(inst.get_output() or "")
                                    # Match Lclass/name/Here;->methodName(params)return
                                    match = re.search(r"(L[^;]+;)->([a-zA-Z0-9_<>]+)\(([^)]*)\)(.*)", output)
                                    if match:
                                        callee_class = match.group(1)
                                        callee_method = match.group(2)
                                        callee_desc = f"({match.group(3)}){match.group(4)}"
                                        callee_id = f"{callee_class}->{callee_method}{callee_desc}"
                                        
                                        # Add edge caller_id -> callee_id
                                        adj.setdefault(caller_id, set()).add(callee_id)
                                        
                                        # If callee is not yet in node_metadata, create it
                                        if callee_id not in node_metadata:
                                            callee_type = "method"
                                            callee_tags = []
                                            if callee_method in SOURCES_LIST:
                                                callee_type = "source"
                                                callee_tags.append(SOURCES_LIST[callee_method])
                                            elif callee_method in SINKS_LIST:
                                                callee_type = "sink"
                                                callee_tags.append(SINKS_LIST[callee_method])
                                                
                                            node_metadata[callee_id] = {
                                                "class": callee_class,
                                                "method": callee_method,
                                                "type": callee_type,
                                                "tags": callee_tags,
                                                "risk": "benign"
                                            }
                            except Exception:
                                pass
                    except Exception:
                        pass
        except Exception:
            pass

    # 5. Extract entrypoints, sources, and sinks for slicing
    entrypoints = {nid for nid, meta in node_metadata.items() if meta["type"] == "entrypoint"}
    sources = {nid for nid, meta in node_metadata.items() if meta["type"] == "source"}
    sinks = {nid for nid, meta in node_metadata.items() if meta["type"] == "sink"}

    # Include any methods involved in the verified dangerous api chains
    chains = findings.get("dangerous_api_chains", [])
    for chain in chains:
        desc = chain.get("description", "")
        # Find methods mentioned in description, e.g. "flow in com.example.Class: source -> sink"
        class_match = re.search(r"flow in ([a-zA-Z0-9_\.]+):", desc)
        if class_match:
            cname = "L" + class_match.group(1).replace(".", "/") + ";"
            for nid, meta in node_metadata.items():
                if meta["class"] == cname:
                    entrypoints.add(nid) # Add to entrypoints to preserve in slice

    # 6. Run bidirectional slicing to get the interesting subgraph
    # Forward reachability from entrypoints + sources (limit depth to 4 to avoid massive graphs)
    reachable_forward = set()
    queue = list(entrypoints | sources)
    visited = set(queue)
    depth_map = {nid: 0 for nid in queue}
    while queue:
        curr = queue.pop(0)
        reachable_forward.add(curr)
        curr_depth = depth_map.get(curr, 0)
        if curr_depth >= 4:
            continue
        for neighbor in adj.get(curr, []):
            if neighbor not in visited:
                visited.add(neighbor)
                depth_map[neighbor] = curr_depth + 1
                queue.append(neighbor)

    # Backward reachability from sinks
    rev_adj = {}
    for parent, children in adj.items():
        for child in children:
            rev_adj.setdefault(child, set()).add(parent)
            
    reachable_backward = set()
    queue = list(sinks)
    visited = set(queue)
    depth_map = {nid: 0 for nid in queue}
    while queue:
        curr = queue.pop(0)
        reachable_backward.add(curr)
        curr_depth = depth_map.get(curr, 0)
        if curr_depth >= 4:
            continue
        for neighbor in rev_adj.get(curr, []):
            if neighbor not in visited:
                visited.add(neighbor)
                depth_map[neighbor] = curr_depth + 1
                queue.append(neighbor)

    # Subgraph nodes are the intersection
    subgraph_nodes = reachable_forward & reachable_backward
    subgraph_nodes |= (entrypoints & reachable_backward)
    subgraph_nodes |= (sinks & reachable_forward)
    subgraph_nodes |= sources

    # 7. Trace malicious paths from sources to sinks within the subgraph to label risks
    malicious_nodes = set()
    malicious_edges = set()
    
    for src in (sources & subgraph_nodes):
        q = [[src]]
        visited_paths = {src}
        while q:
            path = q.pop(0)
            last = path[-1]
            if last in sinks:
                for node in path:
                    malicious_nodes.add(node)
                for i in range(len(path) - 1):
                    malicious_edges.add((path[i], path[i+1]))
                continue
            for neighbor in adj.get(last, []):
                if neighbor in subgraph_nodes and neighbor not in visited_paths:
                    visited_paths.add(neighbor)
                    q.append(path + [neighbor])

    # Tracing from entrypoints to sources (permission escalation) - mark as high-risk
    high_risk_nodes = set()
    high_risk_edges = set()
    for ep in (entrypoints & subgraph_nodes):
        q = [[ep]]
        visited_paths = {ep}
        while q:
            path = q.pop(0)
            last = path[-1]
            if last in sources:
                for node in path:
                    high_risk_nodes.add(node)
                for i in range(len(path) - 1):
                    high_risk_edges.add((path[i], path[i+1]))
                continue
            for neighbor in adj.get(last, []):
                if neighbor in subgraph_nodes and neighbor not in visited_paths:
                    visited_paths.add(neighbor)
                    q.append(path + [neighbor])

    # 8. Build final JSON lists
    final_nodes = []
    final_edges = []
    
    subgraph_nodes = list(subgraph_nodes)[:150]
    subgraph_nodes_set = set(subgraph_nodes)

    def clean_label(nid):
        try:
            parts = nid.split("->")
            cname = parts[0].strip("L;").split("/")[-1]
            mname = parts[1].split("(")[0]
            return f"{cname}.{mname}()"
        except Exception:
            return nid

    for nid in subgraph_nodes_set:
        meta = node_metadata[nid]
        risk = "benign"
        if nid in malicious_nodes:
            risk = "malicious"
        elif nid in high_risk_nodes:
            risk = "high-risk"
            
        final_nodes.append({
            "id": nid,
            "label": clean_label(nid),
            "class": meta["class"].strip("L;").replace("/", "."),
            "method": meta["method"],
            "type": meta["type"],
            "tags": meta["tags"],
            "risk": risk
        })

    edge_counter = 0
    for parent in subgraph_nodes_set:
        for child in adj.get(parent, []):
            if child in subgraph_nodes_set:
                risk = "benign"
                if (parent, child) in malicious_edges:
                    risk = "malicious"
                elif (parent, child) in high_risk_edges:
                    risk = "high-risk"
                    
                edge_counter += 1
                final_edges.append({
                    "id": f"e-{edge_counter}",
                    "from": parent,
                    "to": child,
                    "kind": "invoke",
                    "risk": risk
                })

    findings["callgraph"] = {
        "nodes": final_nodes,
        "edges": final_edges
    }

def run_analysis(apk_path: str, output_path: str):
    findings = {
        "suspicious_strings": [],
        "dangerous_api_chains": [],
        "risky_classes": [],
        "score": 0,
        "metadata": {
            "taint_analysis_skipped": False,
            "method_instructions_truncated": False,
            "max_instructions_per_method": 1500,
            "max_dex_size_for_taint_mb": 30,
            "total_dex_size_bytes": 0
        }
    }

    try:
        a = APK(apk_path)
        findings["package_name"] = a.get_package() or ""
        findings["launcher_activity"] = a.get_main_activity() or ""
        findings["is_signed"] = a.is_signed()
        findings["certificate_info"] = extract_certificate_info(a)
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
            findings["metadata"]["method_instructions_truncated"] = True

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
        findings["metadata"]["total_dex_size_bytes"] = total_dex_size
        skip_taint = total_dex_size > 30 * 1024 * 1024
        findings["metadata"]["taint_analysis_skipped"] = skip_taint
        
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
                            findings["metadata"]["method_instructions_truncated"] = True
                            
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
            print(f"Skipping taint analysis: DEX size {total_dex_size / 1024 / 1024:.2f} MB is > 30 MB limit.")

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

    # 5. Extract Smali sources from top suspicious classes
    try:
        findings["smali_sources"] = score_and_select_classes_smali(
            d_list, 
            findings.get("dangerous_api_chains", []), 
            findings.get("package_name", "")
        )
    except Exception as e:
        print(f"Error selecting/disassembling Smali classes: {e}")
        findings["smali_sources"] = {}

    # 6. Generate Behavioral Call Graph
    try:
        generate_call_graph_data(d_list, findings)
    except Exception as e:
        print(f"Error generating call graph data: {e}")
        findings["callgraph"] = {"nodes": [], "edges": []}

    with open(output_path, "w") as f:
        json.dump(findings, f, default=str)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: androguard_analyzer.py <apk_path> <output_json_path>")
        sys.exit(1)
    run_analysis(sys.argv[1], sys.argv[2])
