"""
frida_hooks.py — Modular Frida instrumentation hook packs for Kavach AI.

Each pack instruments a specific Android API surface.
All hooks emit normalized events via send() with schema:
  {
    category:      string  e.g. "prefs.read", "network.http"
    action:        string  e.g. "get", "request", "load"
    severity_hint: string  "low" | "medium" | "high" | "critical"
    class_name:    string  Java class hooked
    method:        string  method name
    args:          object  relevant arguments (truncated)
    evidence:      string  human-readable finding summary
  }
"""

from typing import List

# --------------------------------------------------------------------------- #
# Shared helpers injected into every assembled script
# --------------------------------------------------------------------------- #
_HELPER_JS = """
// ── Kavach helpers ──────────────────────────────────────────────────────────
function _trunc(s, n) {
    if (s === null || s === undefined) return "";
    s = String(s);
    return s.length > n ? s.substring(0, n) + "…" : s;
}

function _emit(category, action, severity, cls, method, args, evidence) {
    send({
        category:      category,
        action:        action,
        severity_hint: severity,
        class_name:    cls,
        method:        method,
        args:          args  || {},
        evidence:      evidence || ""
    });
}
// ────────────────────────────────────────────────────────────────────────────
"""

# --------------------------------------------------------------------------- #
# Pack: shared_prefs
# --------------------------------------------------------------------------- #
_PACK_SHARED_PREFS = """
// ── SharedPreferences hooks ─────────────────────────────────────────────────
try {
    var _CtxW = Java.use("android.content.ContextWrapper");
    _CtxW.getSharedPreferences.overload("java.lang.String", "int").implementation = function(name, mode) {
        _emit("prefs.read", "get_prefs", "low",
              "android.content.ContextWrapper", "getSharedPreferences",
              { name: _trunc(name,80), mode: mode },
              "SharedPreferences accessed: " + _trunc(name,80) + " (mode=" + mode + ")");
        return this.getSharedPreferences(name, mode);
    };
} catch(e) {}

try {
    var _SPImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
    _SPImpl.putString.implementation = function(key, value) {
        var v = _trunc(value, 120);
        _emit("prefs.write", "put_string", "medium",
              "SharedPreferencesImpl$EditorImpl", "putString",
              { key: _trunc(key,60), value: v },
              "SharedPreferences putString: " + _trunc(key,60) + " = " + v);
        return this.putString(key, value);
    };
    _SPImpl.putInt.implementation = function(key, value) {
        _emit("prefs.write", "put_int", "low",
              "SharedPreferencesImpl$EditorImpl", "putInt",
              { key: _trunc(key,60), value: value },
              "SharedPreferences putInt: " + _trunc(key,60));
        return this.putInt(key, value);
    };
} catch(e) {}
"""

# --------------------------------------------------------------------------- #
# Pack: file_io
# --------------------------------------------------------------------------- #
_PACK_FILE_IO = """
// ── File I/O hooks ──────────────────────────────────────────────────────────
try {
    var _FOS = Java.use("java.io.FileOutputStream");
    _FOS.$init.overload("java.io.File").implementation = function(f) {
        try {
            var p = f.getAbsolutePath();
            if (p.indexOf("/proc") !== 0 && p.indexOf("/sys") !== 0) {
                _emit("file.write", "open", "low",
                      "java.io.FileOutputStream", "<init>",
                      { path: _trunc(p, 150) },
                      "File write opened: " + _trunc(p, 150));
            }
        } catch(e2) {}
        this.$init(f);
    };
} catch(e) {}

try {
    var _FIS = Java.use("java.io.FileInputStream");
    _FIS.$init.overload("java.io.File").implementation = function(f) {
        try {
            var p = f.getAbsolutePath();
            if (p.indexOf("/proc") !== 0 && p.indexOf("/sys") !== 0 && p.indexOf("/dev") !== 0) {
                _emit("file.read", "open", "low",
                      "java.io.FileInputStream", "<init>",
                      { path: _trunc(p, 150) },
                      "File read opened: " + _trunc(p, 150));
            }
        } catch(e2) {}
        this.$init(f);
    };
} catch(e) {}
"""

# --------------------------------------------------------------------------- #
# Pack: sqlite
# --------------------------------------------------------------------------- #
_PACK_SQLITE = """
// ── SQLite hooks ─────────────────────────────────────────────────────────────
try {
    var _SQLite = Java.use("android.database.sqlite.SQLiteDatabase");
    _SQLite.execSQL.overload("java.lang.String").implementation = function(sql) {
        _emit("db.write", "exec_sql", "medium",
              "android.database.sqlite.SQLiteDatabase", "execSQL",
              { sql: _trunc(sql, 200) },
              "SQLite execSQL: " + _trunc(sql, 100));
        return this.execSQL(sql);
    };
    _SQLite.rawQuery.overload("java.lang.String", "[Ljava.lang.String;").implementation = function(sql, args) {
        _emit("db.query", "raw_query", "low",
              "android.database.sqlite.SQLiteDatabase", "rawQuery",
              { sql: _trunc(sql, 200) },
              "SQLite rawQuery: " + _trunc(sql, 100));
        return this.rawQuery(sql, args);
    };
} catch(e) {}
"""

# --------------------------------------------------------------------------- #
# Pack: network
# --------------------------------------------------------------------------- #
_PACK_NETWORK = """
// ── Network hooks ────────────────────────────────────────────────────────────
try {
    var _URL = Java.use("java.net.URL");
    _URL.openConnection.overload().implementation = function() {
        var u = this.toString();
        var scheme = this.getProtocol();
        var cat = (scheme === "https") ? "network.tls" : "network.http";
        var sev = (scheme === "https") ? "low" : "medium";
        _emit(cat, "open_connection", sev,
              "java.net.URL", "openConnection",
              { url: _trunc(u, 200), scheme: scheme },
              "Network connection: " + _trunc(u, 150));
        return this.openConnection();
    };
} catch(e) {}

try {
    var _HURLC = Java.use("java.net.HttpURLConnection");
    _HURLC.connect.implementation = function() {
        try {
            var u = this.getURL().toString();
            var m = this.getRequestMethod();
            _emit("network.http", "connect", "medium",
                  "java.net.HttpURLConnection", "connect",
                  { url: _trunc(u, 200), method: m },
                  "HTTP connect (" + m + "): " + _trunc(u, 150));
        } catch(e2) {}
        return this.connect();
    };
} catch(e) {}

try {
    var _RealCall = Java.use("okhttp3.RealCall");
    _RealCall.enqueue.implementation = function(callback) {
        try {
            var req = this.request();
            var u = req.url().toString();
            var m = req.method();
            _emit("network.http", "enqueue_okhttp", "medium",
                  "okhttp3.RealCall", "enqueue",
                  { url: _trunc(u, 200), method: m },
                  "OkHttp enqueue (" + m + "): " + _trunc(u, 150));
        } catch(e2) {}
        return this.enqueue(callback);
    };
    _RealCall.execute.implementation = function() {
        try {
            var req = this.request();
            var u = req.url().toString();
            var m = req.method();
            _emit("network.http", "execute_okhttp", "medium",
                  "okhttp3.RealCall", "execute",
                  { url: _trunc(u, 200), method: m },
                  "OkHttp execute (" + m + "): " + _trunc(u, 150));
        } catch(e2) {}
        return this.execute();
    };
} catch(e) {}
"""

# --------------------------------------------------------------------------- #
# Pack: webview
# --------------------------------------------------------------------------- #
_PACK_WEBVIEW = """
// ── WebView hooks ────────────────────────────────────────────────────────────
try {
    var _WV = Java.use("android.webkit.WebView");
    _WV.loadUrl.overload("java.lang.String").implementation = function(url) {
        _emit("webview.load_url", "load", "medium",
              "android.webkit.WebView", "loadUrl",
              { url: _trunc(url, 200) },
              "WebView loadUrl: " + _trunc(url, 150));
        this.loadUrl(url);
    };
} catch(e) {}

try {
    var _WVC = Java.use("android.webkit.WebViewClient");
    _WVC.shouldOverrideUrlLoading.overload(
        "android.webkit.WebView", "java.lang.String").implementation = function(view, url) {
        _emit("webview.load_url", "redirect", "medium",
              "android.webkit.WebViewClient", "shouldOverrideUrlLoading",
              { url: _trunc(url, 200) },
              "WebView redirect: " + _trunc(url, 150));
        return this.shouldOverrideUrlLoading(view, url);
    };
} catch(e) {}
"""

# --------------------------------------------------------------------------- #
# Pack: intents
# --------------------------------------------------------------------------- #
_PACK_INTENTS = """
// ── Intent hooks ─────────────────────────────────────────────────────────────
try {
    var _CW_intent = Java.use("android.content.ContextWrapper");
    _CW_intent.startActivity.overload("android.content.Intent").implementation = function(intent) {
        try {
            var action    = intent.getAction()    ? String(intent.getAction())    : "";
            var component = intent.getComponent() ? String(intent.getComponent().flattenToString()) : "";
            var pkg       = intent.getPackage()   ? String(intent.getPackage())   : "";
            _emit("intent.send", "start_activity", "low",
                  "android.content.ContextWrapper", "startActivity",
                  { action: _trunc(action,80), component: _trunc(component,120), package: _trunc(pkg,60) },
                  "Activity started: " + _trunc(component || action, 120));
        } catch(e2) {}
        return this.startActivity(intent);
    };
    _CW_intent.sendBroadcast.overload("android.content.Intent").implementation = function(intent) {
        try {
            var action = intent.getAction() ? String(intent.getAction()) : "";
            _emit("intent.send", "broadcast", "low",
                  "android.content.ContextWrapper", "sendBroadcast",
                  { action: _trunc(action, 120) },
                  "Broadcast sent: " + _trunc(action, 120));
        } catch(e2) {}
        return this.sendBroadcast(intent);
    };
} catch(e) {}

try {
    var _BR = Java.use("android.content.BroadcastReceiver");
    _BR.onReceive.implementation = function(ctx, intent) {
        try {
            var action = intent.getAction() ? String(intent.getAction()) : "";
            _emit("intent.receive", "on_receive", "low",
                  "android.content.BroadcastReceiver", "onReceive",
                  { action: _trunc(action, 120) },
                  "Broadcast received: " + _trunc(action, 120));
        } catch(e2) {}
        return this.onReceive(ctx, intent);
    };
} catch(e) {}
"""

# --------------------------------------------------------------------------- #
# Pack: crypto
# --------------------------------------------------------------------------- #
_PACK_CRYPTO = """
// ── Crypto hooks ─────────────────────────────────────────────────────────────
try {
    var _SKS = Java.use("javax.crypto.spec.SecretKeySpec");
    _SKS.$init.overload("[B", "java.lang.String").implementation = function(key, alg) {
        var b64 = "";
        try { b64 = Java.use("android.util.Base64").encodeToString(key, 2); } catch(e2) {}
        _emit("crypto.key", "load", "high",
              "javax.crypto.spec.SecretKeySpec", "<init>",
              { algorithm: _trunc(String(alg), 40), key_preview: _trunc(b64, 40) },
              "Crypto key loaded for " + _trunc(String(alg), 40));
        this.$init(key, alg);
    };
} catch(e) {}

try {
    var _Cipher = Java.use("javax.crypto.Cipher");
    _Cipher.doFinal.overload("[B").implementation = function(input) {
        var result = this.doFinal(input);
        var alg    = _trunc(String(this.getAlgorithm()), 60);
        var mode   = this.getOpmode ? this.getOpmode() : -1;
        var cat    = (mode === 2) ? "crypto.decrypt" : "crypto.encrypt";
        var action = (mode === 2) ? "decrypt" : "encrypt";
        _emit(cat, action, "high",
              "javax.crypto.Cipher", "doFinal",
              { algorithm: alg },
              "Cipher " + action + " using " + alg);
        return result;
    };
    _Cipher.doFinal.overload().implementation = function() {
        var result = this.doFinal();
        var alg    = _trunc(String(this.getAlgorithm()), 60);
        _emit("crypto.encrypt", "finalize", "medium",
              "javax.crypto.Cipher", "doFinal()",
              { algorithm: alg },
              "Cipher finalize using " + alg);
        return result;
    };
} catch(e) {}
"""

# --------------------------------------------------------------------------- #
# Pack: native
# --------------------------------------------------------------------------- #
_PACK_NATIVE = """
// ── Native library hooks ─────────────────────────────────────────────────────
try {
    var _Sys = Java.use("java.lang.System");
    _Sys.loadLibrary.implementation = function(libname) {
        _emit("native.lib.load", "load_library", "medium",
              "java.lang.System", "loadLibrary",
              { libname: _trunc(String(libname), 80) },
              "Native library loaded: lib" + _trunc(String(libname), 80) + ".so");
        this.loadLibrary(libname);
    };
} catch(e) {}

try {
    var _RT = Java.use("java.lang.Runtime");
    _RT.load.overload("java.lang.String").implementation = function(path) {
        _emit("native.lib.load", "load_path", "medium",
              "java.lang.Runtime", "load",
              { path: _trunc(String(path), 150) },
              "Native library loaded from path: " + _trunc(String(path), 150));
        return this.load(path);
    };
} catch(e) {}
"""

# --------------------------------------------------------------------------- #
# Pack: evasion  (anti_vm / anti_debug / anti_hook signals)
# --------------------------------------------------------------------------- #
_VM_PROP_KEYWORDS = [
    "ro.build.fingerprint", "ro.product.model", "ro.product.manufacturer",
    "ro.build.tags", "ro.hardware", "ro.product.board", "ro.product.brand",
    "ro.kernel.qemu", "ro.secure", "ro.debuggable"
]

_PACK_EVASION = (
    """
// ── Evasion detection hooks ──────────────────────────────────────────────────
try {
    var _Dbg = Java.use("android.os.Debug");
    _Dbg.isDebuggerConnected.implementation = function() {
        var r = this.isDebuggerConnected();
        _emit("anti_debug.signal", "debugger_check", "medium",
              "android.os.Debug", "isDebuggerConnected",
              { result: r },
              "Debugger presence check (result=" + r + ")");
        return r;
    };
} catch(e) {}

try {
    var _SysProp = Java.use("android.os.SystemProperties");
    var _vmKeys = """ + str(_VM_PROP_KEYWORDS) + """;
    _SysProp.get.overload("java.lang.String").implementation = function(key) {
        var r = this.get(key);
        var k = String(key);
        var isVM = _vmKeys.some(function(vk) { return k.indexOf(vk) !== -1; });
        if (isVM) {
            _emit("anti_vm.signal", "property_check", "high",
                  "android.os.SystemProperties", "get",
                  { key: _trunc(k, 80), value: _trunc(r, 80) },
                  "VM property check: " + _trunc(k, 80) + " = " + _trunc(r, 60));
        }
        return r;
    };
} catch(e) {}

try {
    var _RTExec = Java.use("java.lang.Runtime");
    _RTExec.exec.overload("java.lang.String").implementation = function(cmd) {
        _emit("process.exec", "shell_exec", "high",
              "java.lang.Runtime", "exec",
              { cmd: _trunc(String(cmd), 150) },
              "Runtime.exec: " + _trunc(String(cmd), 120));
        return this.exec(cmd);
    };
} catch(e) {}
"""
)

# --------------------------------------------------------------------------- #
# Pack: clipboard
# --------------------------------------------------------------------------- #
_PACK_CLIPBOARD = """
// ── Clipboard hooks ──────────────────────────────────────────────────────────
try {
    var _CM = Java.use("android.content.ClipboardManager");
    _CM.getPrimaryClip.implementation = function() {
        var clip = this.getPrimaryClip();
        var text = "";
        try {
            if (clip && clip.getItemCount() > 0) {
                text = _trunc(String(clip.getItemAt(0).coerceToText(this)), 100);
            }
        } catch(e2) {}
        _emit("clipboard.read", "get_primary_clip", "medium",
              "android.content.ClipboardManager", "getPrimaryClip",
              { preview: text },
              "Clipboard read" + (text ? ": " + text : ""));
        return clip;
    };
    _CM.setPrimaryClip.implementation = function(clip) {
        var text = "";
        try {
            if (clip && clip.getItemCount() > 0) {
                text = _trunc(String(clip.getItemAt(0).coerceToText(null)), 100);
            }
        } catch(e2) {}
        _emit("clipboard.write", "set_primary_clip", "medium",
              "android.content.ClipboardManager", "setPrimaryClip",
              { preview: text },
              "Clipboard write" + (text ? ": " + text : ""));
        return this.setPrimaryClip(clip);
    };
} catch(e) {}
"""

# --------------------------------------------------------------------------- #
# Pack: permissions
# --------------------------------------------------------------------------- #
_PACK_PERMISSIONS = """
// ── Permission request hooks ─────────────────────────────────────────────────
try {
    var _AC = Java.use("androidx.core.app.ActivityCompat");
    _AC.requestPermissions.overload(
        "android.app.Activity", "[Ljava.lang.String;", "int"
    ).implementation = function(activity, perms, code) {
        var pList = [];
        try {
            for (var i = 0; i < perms.length; i++) {
                pList.push(String(perms[i]));
            }
        } catch(e2) {}
        _emit("permission.request", "request_permissions", "medium",
              "androidx.core.app.ActivityCompat", "requestPermissions",
              { permissions: pList, request_code: code },
              "Permission requested: " + pList.join(", "));
        return this.requestPermissions(activity, perms, code);
    };
} catch(e) {}

try {
    var _ACSupport = Java.use("android.support.v4.app.ActivityCompat");
    _ACSupport.requestPermissions.overload(
        "android.app.Activity", "[Ljava.lang.String;", "int"
    ).implementation = function(activity, perms, code) {
        var pList = [];
        try {
            for (var i = 0; i < perms.length; i++) {
                pList.push(String(perms[i]));
            }
        } catch(e2) {}
        _emit("permission.request", "request_permissions", "medium",
              "android.support.v4.app.ActivityCompat", "requestPermissions",
              { permissions: pList, request_code: code },
              "Permission requested: " + pList.join(", "));
        return this.requestPermissions(activity, perms, code);
    };
} catch(e) {}
"""

# --------------------------------------------------------------------------- #
# Pack: sms_telephony
# --------------------------------------------------------------------------- #
_PACK_SMS_TELEPHONY = """
// ── SMS & Telephony hooks ────────────────────────────────────────────────────
try {
    var _SmsM = Java.use("android.telephony.SmsManager");
    _SmsM.sendTextMessage.overload(
        "java.lang.String", "java.lang.String", "java.lang.String",
        "android.app.PendingIntent", "android.app.PendingIntent"
    ).implementation = function(dest, sc, text, sent, deliv) {
        _emit("telephony.sms", "send", "critical",
              "android.telephony.SmsManager", "sendTextMessage",
              { destination: _trunc(dest, 40), text_length: text ? text.length : 0 },
              "Outgoing SMS intercepted to dest=" + _trunc(dest, 30) + " text=" + _trunc(text, 80));
        return this.sendTextMessage(dest, sc, text, sent, deliv);
    };
} catch(e) {}

try {
    var _TelephonyM = Java.use("android.telephony.TelephonyManager");
    _TelephonyM.getDeviceId.overload().implementation = function() {
        var r = this.getDeviceId();
        _emit("spy.device", "get_device_id", "high",
              "android.telephony.TelephonyManager", "getDeviceId",
              {},
              "Device hardware ID exfiltrated (IMEI/MEID)");
        return r;
    };
    _TelephonyM.getSubscriberId.overload().implementation = function() {
        var r = this.getSubscriberId();
        _emit("spy.device", "get_subscriber_id", "high",
              "android.telephony.TelephonyManager", "getSubscriberId",
              {},
              "Subscriber IMSI code exfiltrated");
        return r;
    };
    _TelephonyM.getLine1Number.overload().implementation = function() {
        var r = this.getLine1Number();
        _emit("spy.device", "get_line1_number", "critical",
              "android.telephony.TelephonyManager", "getLine1Number",
              {},
              "Sim card telephone number exfiltrated");
        return r;
    };
} catch(e) {}
"""

# --------------------------------------------------------------------------- #
# Pack: location_gps
# --------------------------------------------------------------------------- #
_PACK_LOCATION_GPS = """
// ── Location & GPS hooks ─────────────────────────────────────────────────────
try {
    var _LocM = Java.use("android.location.LocationManager");
    _LocM.getLastKnownLocation.overload("java.lang.String").implementation = function(provider) {
        var r = this.getLastKnownLocation(provider);
        _emit("spy.location", "get_last_location", "medium",
              "android.location.LocationManager", "getLastKnownLocation",
              { provider: provider },
              "GPS location exfiltrated using provider=" + provider);
        return r;
    };
} catch(e) {}
"""

# --------------------------------------------------------------------------- #
# Pack: media_recorder
# --------------------------------------------------------------------------- #
_PACK_MEDIA_RECORDER = """
// ── Media Recorder hooks ─────────────────────────────────────────────────────
try {
    var _MR = Java.use("android.media.MediaRecorder");
    _MR.prepare.implementation = function() {
        _emit("spy.media", "record_prepare", "high",
              "android.media.MediaRecorder", "prepare",
              {},
              "Media recorder initialization detected (mic/camera tracing)");
        return this.prepare();
    };
    _MR.start.implementation = function() {
        _emit("spy.media", "record_start", "critical",
              "android.media.MediaRecorder", "start",
              {},
              "Background audio/video recording started active capture");
        return this.start();
    };
} catch(e) {}
"""

# --------------------------------------------------------------------------- #
# Pack: dynamic_loading
# --------------------------------------------------------------------------- #
_PACK_DYNAMIC_LOADING = """
// ── Dynamic Code Loading hooks ───────────────────────────────────────────────
try {
    var _DexCL = Java.use("dalvik.system.DexClassLoader");
    _DexCL.$init.implementation = function(dexPath, optPath, libPath, parent) {
        _emit("evasion.dynamic_load", "load_dex", "critical",
              "dalvik.system.DexClassLoader", "<init>",
              { path: _trunc(dexPath, 150) },
              "Dynamic DEX bytecode payload loaded: " + _trunc(dexPath, 100));
        this.$init(dexPath, optPath, libPath, parent);
    };
} catch(e) {}

try {
    var _PathCL = Java.use("dalvik.system.PathClassLoader");
    _PathCL.$init.overload("java.lang.String", "java.lang.ClassLoader").implementation = function(path, parent) {
        _emit("evasion.dynamic_load", "load_path_dex", "high",
              "dalvik.system.PathClassLoader", "<init>",
              { path: _trunc(path, 150) },
              "PathClassLoader loaded dex/apk resource: " + _trunc(path, 100));
        this.$init(path, parent);
    };
} catch(e) {}
"""

# --------------------------------------------------------------------------- #
# Pack: process_builder
# --------------------------------------------------------------------------- #
_PACK_PROCESS_BUILDER = """
// ── Process Builder shell execution hooks ────────────────────────────────────
try {
    var _PB = Java.use("java.lang.ProcessBuilder");
    _PB.start.implementation = function() {
        var cmd = this.command().toString();
        _emit("process.exec", "process_builder_start", "critical",
              "java.lang.ProcessBuilder", "start",
              { command: _trunc(cmd, 200) },
              "ProcessBuilder shell command executed: " + _trunc(cmd, 120));
        return this.start();
    };
} catch(e) {}
"""

# --------------------------------------------------------------------------- #
# Pack: app_listing
# --------------------------------------------------------------------------- #
_PACK_APP_LISTING = """
// ── Package Enumeration hooks ────────────────────────────────────────────────
try {
    var _PM = Java.use("android.app.ApplicationPackageManager");
    _PM.getInstalledPackages.overload("int").implementation = function(flags) {
        _emit("spy.app_list", "get_installed_packages", "medium",
              "android.app.ApplicationPackageManager", "getInstalledPackages",
              { flags: flags },
              "Malware application enumerating installed device packages (target checklist scan)");
        return this.getInstalledPackages(flags);
    };
} catch(e) {}
"""

# --------------------------------------------------------------------------- #
# Registry and assembler
# --------------------------------------------------------------------------- #
ALL_PACKS: dict = {
    "shared_prefs":    _PACK_SHARED_PREFS,
    "file_io":         _PACK_FILE_IO,
    "sqlite":          _PACK_SQLITE,
    "network":         _PACK_NETWORK,
    "webview":         _PACK_WEBVIEW,
    "intents":         _PACK_INTENTS,
    "crypto":          _PACK_CRYPTO,
    "native":          _PACK_NATIVE,
    "evasion":         _PACK_EVASION,
    "clipboard":       _PACK_CLIPBOARD,
    "permissions":     _PACK_PERMISSIONS,
    "sms_telephony":   _PACK_SMS_TELEPHONY,
    "location_gps":    _PACK_LOCATION_GPS,
    "media_recorder":  _PACK_MEDIA_RECORDER,
    "dynamic_loading": _PACK_DYNAMIC_LOADING,
    "process_builder": _PACK_PROCESS_BUILDER,
    "app_listing":     _PACK_APP_LISTING,
}

# Core packs always loaded — lightweight, high signal
DEFAULT_PACKS: List[str] = [
    "shared_prefs", "network", "crypto", "native", "clipboard", "permissions",
    "sms_telephony", "location_gps", "media_recorder", "dynamic_loading", "process_builder", "app_listing"
]


def build_frida_script(active_packs: List[str]) -> str:
    """
    Assemble a single Java.perform Frida script from the requested hook packs.
    Unknown pack names are silently skipped.
    """
    selected = [p for p in active_packs if p in ALL_PACKS]
    packs_js = "\n\n".join(ALL_PACKS[p] for p in selected)
    packs_label = ", ".join(selected)

    return f"""
Java.perform(function() {{
    console.log("[Kavach] Instrumentation active. Packs: {packs_label}");

{_HELPER_JS}

{packs_js}

    console.log("[Kavach] All hook packs installed.");
}});
"""


def select_packs_from_signals(static_signals: dict) -> List[str]:
    """
    Return an ordered, deduplicated list of hook packs to activate
    based on what static analysis signals were detected.
    """
    packs = list(DEFAULT_PACKS)  # start with core

    if static_signals.get("has_webview"):
        packs.append("webview")
    if static_signals.get("has_exported_receivers") or static_signals.get("has_exported_activities"):
        packs.append("intents")
    if static_signals.get("has_anti_vm") or static_signals.get("has_obfuscation") or static_signals.get("has_packer"):
        packs.append("evasion")
    if static_signals.get("has_data_storage") or static_signals.get("has_sqlite"):
        packs.append("file_io")
        packs.append("sqlite")

    # Deduplicate preserving insertion order
    seen = set()
    result = []
    for p in packs:
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result
