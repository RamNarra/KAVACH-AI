"""
runtime_findings.py — Post-collection clustering engine for Kavach AI.

Takes a list of normalized dynamic events and produces typed RuntimeFinding
objects that become first-class evidence alongside static findings.

Source states:
  "dynamic"      — observed only at runtime
  "correlated"   — confirms a static finding at runtime
  "inconclusive" — static suggests risk but runtime didn't exercise the code path

Confidence model:
  Single weak event              → ~0.45
  Multiple events, same category → ~0.70
  Static + dynamic corroboration → ~0.90
  Partial/incomplete runtime     → capped at 0.60
"""

import re
import datetime
from dataclasses import dataclass, asdict
from collections import defaultdict
from typing import List, Dict, Any, Optional

RF_ID_SMS_INTERCEPTION = "rf_sms_access_or_interception_obs"
RF_ID_OVERLAY_DRAWING  = "rf_overlay_view_drawing_detected"
RF_ID_ACCESSIBILITY_ABUSE = "rf_accessibility_abuse_detected"


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class RuntimeFinding:
    id: str
    title: str
    severity: str                          # CRITICAL HIGH MEDIUM LOW INFO
    category: str                          # MASVS-style label
    summary: str
    evidence_items: List[str]
    sample_events: List[Dict[str, Any]]
    confidence: float                      # 0.0 – 1.0
    source: str                            # "dynamic" | "correlated"
    static_finding_refs: List[str]        # labels of confirmed static findings
    event_count: int
    event_categories: List[str]


def _make_id(title: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", title.lower()).strip("_")[:40]
    return f"rf_{slug}"


def _samples(events: list, n: int = 3) -> list:
    """Return up to n representative events (first, last, middle)."""
    if not events:
        return []
    if len(events) <= n:
        return events
    mid = len(events) // 2
    return [events[0], events[mid], events[-1]][:n]


# --------------------------------------------------------------------------- #
# Sensitive keyword heuristics
# --------------------------------------------------------------------------- #
_AUTH_KEYS = re.compile(
    r"(pass(word)?|token|auth|session|secret|credential|jwt|api_?key|login|pin|otp)",
    re.IGNORECASE
)
_CRED_TABLES = re.compile(
    r"(user|account|cred|login|auth|session|token|profile)",
    re.IGNORECASE
)
_EXTERNAL_SCHEME = re.compile(r"^https?://(?!localhost|127\.0\.0\.1)", re.IGNORECASE)
_HTTP_PLAINTEXT  = re.compile(r"^http://",  re.IGNORECASE)


def _calc_confidence(
    event_count: int,
    has_static_corroboration: bool = False,
    runtime_partial: bool = False,
    base_override: Optional[float] = None,
) -> float:
    """Formalized confidence scoring for a RuntimeFinding."""
    if base_override is not None:
        base = base_override
    elif event_count <= 1:
        base = 0.45
    elif event_count <= 3:
        base = 0.65
    elif event_count <= 8:
        base = 0.75
    else:
        base = 0.82

    if has_static_corroboration:
        base = min(base + 0.18, 0.95)

    if runtime_partial:
        base = min(base, 0.60)

    return round(base, 2)


def _label_static(static_evidence: Optional[dict], category_keyword: str) -> bool:
    """Check if static evidence has any findings matching a category keyword."""
    if not static_evidence:
        return False
    for cat_list in static_evidence.values():
        if not isinstance(cat_list, list):
            continue
        for item in cat_list:
            if isinstance(item, dict):
                haystack = " ".join(str(v) for v in item.values())
                if category_keyword.lower() in haystack.lower():
                    return True
    return False


# --------------------------------------------------------------------------- #
# Clustering rules
# --------------------------------------------------------------------------- #
def cluster_runtime_findings(
    normalized_events: List[Dict[str, Any]],
    static_evidence: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Cluster normalized events into RuntimeFinding objects.
    Returns a list of dicts (serializable for Database / JSON).
    """
    findings: List[RuntimeFinding] = []

    # Group by category for efficient rule evaluation
    by_cat: Dict[str, List[Dict]] = defaultdict(list)
    for ev in normalized_events:
        cat = ev.get("category", "unknown")
        by_cat[cat].append(ev)

    # ── 1. Plaintext network requests ─────────────────────────────────────
    http_plain = [
        e for e in by_cat.get("network.http", [])
        if _HTTP_PLAINTEXT.search(str(e.get("args", {}).get("url", "") or e.get("evidence", "")))
    ]
    if http_plain:
        static_match = _label_static(static_evidence, "cleartext") or _label_static(static_evidence, "http://")
        findings.append(RuntimeFinding(
            id=_make_id("Plaintext HTTP observed at runtime"),
            title="Plaintext HTTP Network Request Observed at Runtime",
            severity="HIGH",
            category="network.cleartext",
            summary=(
                f"The application made {len(http_plain)} unencrypted HTTP request(s) during execution. "
                "Credentials, session tokens, or sensitive data transmitted over cleartext HTTP are "
                "trivially interceptable by network adversaries."
            ),
            evidence_items=[
                f"HTTP connection to: {e.get('args', {}).get('url') or e.get('evidence', '')}"
                for e in http_plain[:8]
            ],
            sample_events=_samples(http_plain),
            confidence=_calc_confidence(len(http_plain), static_match),
            source="correlated" if static_match else "dynamic",
            static_finding_refs=(["cleartext_http_static"] if static_match else []),
            event_count=len(http_plain),
            event_categories=["network.http"],
        ))

    # ── 2. Sensitive SharedPreferences writes ────────────────────────────
    sens_prefs_w = [
        e for e in by_cat.get("prefs.write", [])
        if _AUTH_KEYS.search(str(e.get("args", {}).get("key", "") or ""))
    ]
    if sens_prefs_w:
        static_match = _label_static(static_evidence, "sharedpreferences") or _label_static(static_evidence, "world_readable")
        keys = list({e.get("args", {}).get("key", "?") for e in sens_prefs_w})
        findings.append(RuntimeFinding(
            id=_make_id("Sensitive data in SharedPreferences"),
            title="Auth or Session Data Written to SharedPreferences",
            severity="HIGH",
            category="storage.insecure",
            summary=(
                f"The app wrote sensitive keys ({', '.join(keys[:5])}) to SharedPreferences at runtime. "
                "SharedPreferences is stored in plaintext XML on the device and accessible to attackers "
                "with physical access or root."
            ),
            evidence_items=[
                f"putString({e.get('args',{}).get('key','?')})" for e in sens_prefs_w[:8]
            ],
            sample_events=_samples(sens_prefs_w),
            confidence=_calc_confidence(len(sens_prefs_w), static_match),
            source="correlated" if static_match else "dynamic",
            static_finding_refs=(["data_storage_static"] if static_match else []),
            event_count=len(sens_prefs_w),
            event_categories=["prefs.write"],
        ))

    # ── 3. Any SharedPreferences access (baseline signal) ────────────────
    all_prefs = by_cat.get("prefs.read", []) + by_cat.get("prefs.write", [])
    if all_prefs and not sens_prefs_w:  # only emit generic if no sensitive write found
        findings.append(RuntimeFinding(
            id=_make_id("SharedPreferences access observed"),
            title="SharedPreferences Accessed During Runtime",
            severity="INFO",
            category="storage.prefs",
            summary=(
                f"The application accessed SharedPreferences {len(all_prefs)} time(s). "
                "Confirms dynamic instrumentation is active. No obviously sensitive key names detected."
            ),
            evidence_items=[e.get("evidence", "") for e in all_prefs[:5]],
            sample_events=_samples(all_prefs),
            confidence=_calc_confidence(len(all_prefs), False, base_override=0.60),
            source="dynamic",
            static_finding_refs=[],
            event_count=len(all_prefs),
            event_categories=["prefs.read", "prefs.write"],
        ))

    # ── 4. Cryptographic key material loaded ─────────────────────────────
    crypto_keys = by_cat.get("crypto.key", [])
    if crypto_keys:
        algs = list({e.get("args", {}).get("algorithm", "?") for e in crypto_keys})
        static_match = _label_static(static_evidence, "crypto") or _label_static(static_evidence, "cipher")
        findings.append(RuntimeFinding(
            id=_make_id("Crypto key material loaded"),
            title="Cryptographic Key Material Loaded at Runtime",
            severity="HIGH",
            category="crypto.key_management",
            summary=(
                f"The app loaded cryptographic key material at runtime using: {', '.join(algs[:4])}. "
                "Hardcoded or weakly-derived keys are a significant security risk. "
                "Runtime capture of key bytes enables offline decryption of stored data."
            ),
            evidence_items=[
                f"Key loaded ({e.get('args',{}).get('algorithm','?')}): {e.get('args',{}).get('key_preview','')}"
                for e in crypto_keys[:8]
            ],
            sample_events=_samples(crypto_keys),
            confidence=_calc_confidence(len(crypto_keys), static_match),
            source="correlated" if static_match else "dynamic",
            static_finding_refs=(["crypto_static"] if static_match else []),
            event_count=len(crypto_keys),
            event_categories=["crypto.key"],
        ))

    # ── 5. Crypto encrypt/decrypt operations ────────────────────────────
    crypto_ops = by_cat.get("crypto.encrypt", []) + by_cat.get("crypto.decrypt", [])
    if crypto_ops and not crypto_keys:  # avoid duplicate with key finding
        findings.append(RuntimeFinding(
            id=_make_id("Crypto operations observed"),
            title="Cryptographic Operations Observed at Runtime",
            severity="MEDIUM",
            category="crypto.operations",
            summary=f"The application performed {len(crypto_ops)} cryptographic operation(s) during the trace window.",
            evidence_items=[e.get("evidence", "") for e in crypto_ops[:6]],
            sample_events=_samples(crypto_ops),
            confidence=_calc_confidence(len(crypto_ops), False),
            source="dynamic",
            static_finding_refs=[],
            event_count=len(crypto_ops),
            event_categories=["crypto.encrypt", "crypto.decrypt"],
        ))

    # ── 6. Anti-VM signals ───────────────────────────────────────────────
    anti_vm = by_cat.get("anti_vm.signal", [])
    if anti_vm:
        props = list({e.get("args", {}).get("key", "?") for e in anti_vm})
        static_match = _label_static(static_evidence, "anti_vm") or _label_static(static_evidence, "build.fingerprint")
        findings.append(RuntimeFinding(
            id=_make_id("Anti-VM emulator detection triggered"),
            title="Anti-VM / Emulator Detection Logic Executed at Runtime",
            severity="HIGH",
            category="evasion.anti_vm",
            summary=(
                f"The application queried {len(anti_vm)} environment property(ies) commonly used to detect "
                f"virtual machines or emulators: {', '.join(props[:5])}. "
                "This pattern is used by malware to suppress malicious behavior during analysis."
            ),
            evidence_items=[
                f"Property checked: {e.get('args',{}).get('key','?')} = {e.get('args',{}).get('value','?')}"
                for e in anti_vm[:8]
            ],
            sample_events=_samples(anti_vm),
            confidence=_calc_confidence(len(anti_vm), static_match),
            source="correlated" if static_match else "dynamic",
            static_finding_refs=(["anti_vm_static"] if static_match else []),
            event_count=len(anti_vm),
            event_categories=["anti_vm.signal"],
        ))

    # ── 7. Anti-debug signals ────────────────────────────────────────────
    anti_dbg = by_cat.get("anti_debug.signal", [])
    if anti_dbg:
        findings.append(RuntimeFinding(
            id=_make_id("Anti-debug check observed"),
            title="Debugger Detection Check Executed at Runtime",
            severity="MEDIUM",
            category="evasion.anti_debug",
            summary=(
                f"The application called Debug.isDebuggerConnected() {len(anti_dbg)} time(s). "
                "This is a common anti-analysis measure to detect dynamic instrumentation environments."
            ),
            evidence_items=[e.get("evidence", "") for e in anti_dbg[:5]],
            sample_events=_samples(anti_dbg),
            confidence=_calc_confidence(len(anti_dbg), False, base_override=0.82),
            source="dynamic",
            static_finding_refs=[],
            event_count=len(anti_dbg),
            event_categories=["anti_debug.signal"],
        ))

    # ── 8. WebView loading external domains ─────────────────────────────
    wv_ext = [
        e for e in by_cat.get("webview.load_url", [])
        if _EXTERNAL_SCHEME.search(str(e.get("args", {}).get("url", "") or e.get("evidence", "")))
    ]
    if wv_ext:
        domains = list({re.sub(r"https?://([^/]+).*", r"\1",
                                e.get("args", {}).get("url", "?")) for e in wv_ext})
        static_match = _label_static(static_evidence, "webview")
        findings.append(RuntimeFinding(
            id=_make_id("WebView external domain navigation"),
            title="Runtime WebView Navigation to External Domain",
            severity="MEDIUM",
            category="network.webview",
            summary=(
                f"The app loaded external domain(s) in a WebView at runtime: {', '.join(domains[:4])}. "
                "WebView phishing redirects and credential interception are common attack vectors."
            ),
            evidence_items=[
                f"WebView → {e.get('args',{}).get('url','?')}" for e in wv_ext[:8]
            ],
            sample_events=_samples(wv_ext),
            confidence=_calc_confidence(len(wv_ext), static_match),
            source="correlated" if static_match else "dynamic",
            static_finding_refs=(["webview_static"] if static_match else []),
            event_count=len(wv_ext),
            event_categories=["webview.load_url"],
        ))

    # ── 9. SQLite writes to credential-related tables ────────────────────
    db_cred = [
        e for e in by_cat.get("db.write", []) + by_cat.get("db.query", [])
        if _CRED_TABLES.search(str(e.get("args", {}).get("sql", "") or e.get("evidence", "")))
    ]
    if db_cred:
        findings.append(RuntimeFinding(
            id=_make_id("SQLite credential table write"),
            title="Credential or Session Data Written to SQLite Database",
            severity="HIGH",
            category="storage.database",
            summary=(
                f"The application executed {len(db_cred)} SQLite operation(s) involving tables or queries "
                "that contain credential, session, or user account references."
            ),
            evidence_items=[e.get("evidence", "") or e.get("args", {}).get("sql", "?") for e in db_cred[:8]],
            sample_events=_samples(db_cred),
            confidence=_calc_confidence(len(db_cred), False),
            source="dynamic",
            static_finding_refs=[],
            event_count=len(db_cred),
            event_categories=["db.write", "db.query"],
        ))

    # ── 10. Native library loads ─────────────────────────────────────────
    native = by_cat.get("native.lib.load", [])
    if native:
        libs = list({e.get("args", {}).get("libname", e.get("args", {}).get("path", "?")) for e in native})
        static_match = _label_static(static_evidence, "native") or _label_static(static_evidence, "loadlibrary")
        findings.append(RuntimeFinding(
            id=_make_id("Native library loaded"),
            title="Native Library Loaded at Runtime",
            severity="MEDIUM",
            category="code.native",
            summary=(
                f"The app loaded {len(libs)} native library(ies) during execution: {', '.join(str(l) for l in libs[:4])}. "
                "Native code bypasses Java-layer analysis and may contain additional malicious logic."
            ),
            evidence_items=[e.get("evidence", "") for e in native[:6]],
            sample_events=_samples(native),
            confidence=_calc_confidence(len(native), static_match),
            source="correlated" if static_match else "dynamic",
            static_finding_refs=(["native_static"] if static_match else []),
            event_count=len(native),
            event_categories=["native.lib.load"],
        ))

    # ── 11. Shell command execution ──────────────────────────────────────
    proc_exec = by_cat.get("process.exec", [])
    if proc_exec:
        cmds = [e.get("args", {}).get("cmd", "?") for e in proc_exec[:4]]
        findings.append(RuntimeFinding(
            id=_make_id("Shell command execution"),
            title="Shell Command Execution Observed at Runtime",
            severity="CRITICAL",
            category="code.exec",
            summary=(
                f"The app executed {len(proc_exec)} shell command(s) at runtime via Runtime.exec(). "
                f"Commands observed: {', '.join(str(c) for c in cmds[:3])}. "
                "This is a major red flag indicating possible root escalation, persistence, or data exfiltration."
            ),
            evidence_items=[e.get("evidence", "") for e in proc_exec[:8]],
            sample_events=_samples(proc_exec),
            confidence=_calc_confidence(len(proc_exec), False, base_override=0.90),
            source="dynamic",
            static_finding_refs=[],
            event_count=len(proc_exec),
            event_categories=["process.exec"],
        ))

    # ── 12. Clipboard access ─────────────────────────────────────────────
    clipboard = by_cat.get("clipboard.read", [])
    if clipboard:
        findings.append(RuntimeFinding(
            id=_make_id("Clipboard data read"),
            title="Clipboard Data Read at Runtime",
            severity="MEDIUM",
            category="privacy.clipboard",
            summary=(
                f"The app read clipboard content {len(clipboard)} time(s). "
                "Banking credential theft via clipboard monitoring is a known attack pattern."
            ),
            evidence_items=[e.get("evidence", "") for e in clipboard[:5]],
            sample_events=_samples(clipboard),
            confidence=_calc_confidence(len(clipboard), False),
            source="dynamic",
            static_finding_refs=[],
            event_count=len(clipboard),
            event_categories=["clipboard.read"],
        ))

    # ── 13. Permission requests ──────────────────────────────────────────
    perm_reqs = by_cat.get("permission.request", [])
    if perm_reqs:
        perms = []
        for e in perm_reqs:
            perms.extend(e.get("args", {}).get("permissions", []))
        perms = list(set(str(p) for p in perms))
        findings.append(RuntimeFinding(
            id=_make_id("Runtime permission requests"),
            title="Dangerous Permissions Requested at Runtime",
            severity="MEDIUM",
            category="permissions.runtime",
            summary=(
                f"The app requested {len(perms)} permission(s) at runtime: {', '.join(perms[:5])}."
            ),
            evidence_items=[f"Permission request: {', '.join(perms[:5])}"],
            sample_events=_samples(perm_reqs),
            confidence=_calc_confidence(len(perm_reqs), False),
            source="dynamic",
            static_finding_refs=[],
            event_count=len(perm_reqs),
            event_categories=["permission.request"],
        ))

    # ── 14. SMS Interception ──────────────────────────────────────────────
    sms_events = by_cat.get("telephony.sms", [])
    if sms_events:
        findings.append(RuntimeFinding(
            id=RF_ID_SMS_INTERCEPTION,
            title="SMS Interception and Telephony Access",
            severity="HIGH",
            category="telephony.sms",
            summary=(
                "The application interacted with Android SMS or telephony services at runtime, "
                "indicating potential SMS exfiltration, interception, or OTP capture capabilities."
            ),
            evidence_items=[e.get("evidence", "") for e in sms_events[:5]],
            sample_events=_samples(sms_events),
            confidence=_calc_confidence(len(sms_events), False),
            source="dynamic",
            static_finding_refs=[],
            event_count=len(sms_events),
            event_categories=["telephony.sms"],
        ))

    # ── 15. Window Overlays ──────────────────────────────────────────────
    overlay_events = by_cat.get("window.overlay", [])
    if overlay_events:
        findings.append(RuntimeFinding(
            id=RF_ID_OVERLAY_DRAWING,
            title="Overlay View Drawing Detected",
            severity="CRITICAL",
            category="window.overlay",
            summary=(
                "The application dynamically drew an overlay view using WindowManager, "
                "a technique commonly associated with phishing overlays and credential harvesting."
            ),
            evidence_items=[e.get("evidence", "") for e in overlay_events[:5]],
            sample_events=_samples(overlay_events),
            confidence=_calc_confidence(len(overlay_events), False),
            source="dynamic",
            static_finding_refs=[],
            event_count=len(overlay_events),
            event_categories=["window.overlay"],
        ))

    # ── 16. Accessibility Service Abuse ──────────────────────────────────
    acc_events = by_cat.get("accessibility.abuse", [])
    if acc_events:
        findings.append(RuntimeFinding(
            id=RF_ID_ACCESSIBILITY_ABUSE,
            title="Accessibility Service Abuse Detected",
            severity="CRITICAL",
            category="accessibility.abuse",
            summary=(
                "The application interacted with or registered an Accessibility Service, or queried "
                "active window hierarchy nodes at runtime. Accessibility Service abuse is a highly "
                "dangerous capability used by banking Trojans to automate interactions, bypass permissions, "
                "and log sensitive user keystrokes."
            ),
            evidence_items=[e.get("evidence", "") for e in acc_events[:5]],
            sample_events=_samples(acc_events),
            confidence=_calc_confidence(len(acc_events), False),
            source="dynamic",
            static_finding_refs=[],
            event_count=len(acc_events),
            event_categories=["accessibility.abuse"],
        ))

    # Sort by severity priority
    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: SEV_ORDER.get(f.severity, 9))

    return [asdict(f) for f in findings]


def build_runtime_summary_for_gemini(
    findings: List[Dict[str, Any]],
    run_meta: Dict[str, Any],
    trigger_transcript: List[Dict[str, Any]],
    normalized_events: List[Dict[str, Any]],
    coverage_map: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Build the compact runtime analysis bundle for the Gemini prompt.
    Sends findings + trigger coverage + corroborating samples + notable absences.
    NOT a raw event dump.
    """
    status = run_meta.get("sandbox_status", "UNKNOWN")
    abi_ok = run_meta.get("abi_compatible", False)
    steps_attempted = run_meta.get("trigger_steps_attempted", 0)
    steps_succeeded = run_meta.get("trigger_steps_succeeded", 0)
    event_count = run_meta.get("event_count", 0)
    packs = ", ".join(run_meta.get("hook_packs", []))
    duration = run_meta.get("duration_seconds", 0)
    confidence = run_meta.get("runtime_confidence", "none")
    jadx_partial = run_meta.get("jadx_partial_output", False)

    lines = [
        "--- DYNAMIC SANDBOX ANALYSIS BUNDLE ---",
        f"Sandbox status     : {status}",
        f"ABI compatibility  : {'✓ compatible' if abi_ok else '✗ mismatch — dynamic skipped'}",
        f"Runtime confidence : {confidence.upper()}",
        f"Hook packs loaded  : {packs or 'none'}",
        f"Trigger steps      : {steps_succeeded}/{steps_attempted} succeeded",
        f"Events captured    : {event_count}",
        f"Trace duration     : {duration}s",
    ]
    
    if jadx_partial:
        lines.append(f"LIMITATION         : Static analysis (JADX) timed out; evidence is based on partial decompilation.")
        
    lines.append("")

    if findings:
        lines.append("CLUSTERED RUNTIME FINDINGS:")
        for f in findings:
            lines.append(
                f"  [{f['severity']}] {f['title']} "
                f"(confidence={f['confidence']:.0%}, source={f['source']}, events={f['event_count']})"
            )
            lines.append(f"    \u2192 {f['summary'][:200]}")
            for ev_item in f.get("evidence_items", [])[:3]:
                lines.append(f"      \u2022 {ev_item}")
            lines.append("")
    else:
        lines.append("CLUSTERED RUNTIME FINDINGS: None generated.")
        lines.append("")

    # Evidence summary (compact reducer)
    lines.append("RUNTIME EVIDENCE SUMMARY:")
    lines.append(build_evidence_summary(normalized_events, coverage_map))
    lines.append("")

    # Trigger transcript (compact)
    if trigger_transcript:
        lines.append("TRIGGER PLAYBOOK TRANSCRIPT:")
        for step in trigger_transcript:
            lines.append(
                f"  [{step.get('result','?').upper()}] {step.get('step','?')}: {step.get('action','')}"
            )
        lines.append("")

    # Notable absences
    absences = _build_absences(normalized_events, coverage_map)
    if absences:
        lines.append("NOTABLE ABSENCES (does NOT imply safety):")
        for a in absences:
            lines.append(f"  - {a}")
        lines.append("")

    lines.append("--- END DYNAMIC BUNDLE ---")
    return "\n".join(lines)


def build_evidence_summary(normalized_events: List[Dict[str, Any]],
                           coverage_map: Optional[Dict[str, Any]] = None) -> str:
    """
    Compact prose summary: 'N plaintext HTTP requests to M hosts', etc.
    Used as the Gemini prompt evidence block — not a raw event dump.
    """
    from collections import defaultdict, Counter
    if not normalized_events:
        return "  No runtime events captured."

    by_cat: Dict[str, List] = defaultdict(list)
    for ev in normalized_events:
        by_cat[ev.get("category", "unknown")].append(ev)

    lines = []

    http_plain = [e for e in by_cat.get("network.http", []) if "http://" in str(e.get("args",{}).get("url",""))]
    if http_plain:
        hosts = list({re.sub(r"https?://([^/:]+).*", r"\1", e.get("args",{}).get("url","?")) for e in http_plain})
        lines.append(f"  {len(http_plain)} plaintext HTTP request(s) to {len(hosts)} host(s): {', '.join(hosts[:3])}")

    if by_cat.get("network.tls"):
        lines.append(f"  {len(by_cat['network.tls'])} HTTPS connection(s) observed")

    if by_cat.get("prefs.write"):
        keys = [e.get("args",{}).get("key","?") for e in by_cat["prefs.write"][:4]]
        lines.append(f"  {len(by_cat['prefs.write'])} SharedPreferences write(s): keys={', '.join(str(k) for k in keys)}")

    if by_cat.get("crypto.key"):
        algs = list({e.get("args",{}).get("algorithm","?") for e in by_cat["crypto.key"]})
        lines.append(f"  {len(by_cat['crypto.key'])} crypto key(s) loaded: {', '.join(algs[:3])}")

    if by_cat.get("anti_vm.signal"):
        props = list({e.get("args",{}).get("key","?") for e in by_cat["anti_vm.signal"]})
        lines.append(f"  {len(by_cat['anti_vm.signal'])} emulator detection check(s): {', '.join(props[:3])}")

    if by_cat.get("anti_debug.signal"):
        lines.append(f"  {len(by_cat['anti_debug.signal'])} debugger presence check(s)")

    if by_cat.get("native.lib.load"):
        libs = [e.get("args",{}).get("libname", e.get("args",{}).get("path","?")) for e in by_cat["native.lib.load"]]
        lines.append(f"  {len(libs)} native librar{'ies' if len(libs)!=1 else 'y'} loaded: {', '.join(str(l) for l in libs[:4])}")

    if by_cat.get("webview.load_url"):
        urls = [e.get("args",{}).get("url","?") for e in by_cat["webview.load_url"][:3]]
        lines.append(f"  WebView navigation: {', '.join(urls)}")

    if by_cat.get("process.exec"):
        cmds = [e.get("args",{}).get("cmd","?") for e in by_cat["process.exec"][:3]]
        lines.append(f"  Runtime shell exec: {', '.join(str(c) for c in cmds)}")

    if by_cat.get("db.write") or by_cat.get("db.query"):
        n = len(by_cat.get("db.write",[]))+len(by_cat.get("db.query",[]))
        lines.append(f"  {n} SQLite operation(s) observed")

    if by_cat.get("accessibility.abuse"):
        lines.append(f"  {len(by_cat['accessibility.abuse'])} Accessibility Service event(s) observed")

    cov = coverage_map or {}
    if cov.get("login_simulation_attempted") and not cov.get("login_simulation_effective"):
        lines.append("  Login simulation attempted but no successful form submit detected")
    if not by_cat.get("network.http") and not by_cat.get("network.tls"):
        lines.append("  No outbound network activity observed")
    if not by_cat.get("webview.load_url"):
        lines.append("  No WebView navigation observed")

    return "\n".join(lines) if lines else "  No significant events observed."


def _build_absences(
    normalized_events: List[Dict[str, Any]],
    coverage_map: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Generate notable absence notes — tells Gemini what we tried but didn't observe."""
    cats = {e.get("category") for e in normalized_events}
    cov = coverage_map or {}
    absences = []

    if "network.http" not in cats and "network.tls" not in cats:
        absences.append("No outbound network requests observed despite app launch and interaction. "
                        "App may be offline-only, use certificate pinning, or require credentials to connect.")
    if "webview.load_url" not in cats and cov.get("webview_expected"):
        absences.append("WebView hook active but no WebView URL loads observed. "
                        "WebView may only load on authenticated or specific user-flow paths.")
    if cov.get("login_simulation_attempted") and not cov.get("login_simulation_effective"):
        absences.append("Login form interaction was attempted but effectiveness is uncertain. "
                        "Post-login behavior (network calls, crypto, storage) may not be captured.")
    if cov.get("receivers_tested", 0) == 0 and cov.get("has_exported_receivers"):
        absences.append("Exported broadcast receivers were declared but could not be triggered safely.")

    return absences
