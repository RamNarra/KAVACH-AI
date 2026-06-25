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

import json
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

// TLS Client Hello SNI Interception
try {
    var openSslSocket = Java.use("com.android.org.conscrypt.OpenSSLSocketImpl");
    openSslSocket.setHostname.implementation = function(hostname) {
        _emit("network.tls", "sni_client_hello", "low",
              "com.android.org.conscrypt.OpenSSLSocketImpl", "setHostname",
              { hostname: String(hostname) },
              "TLS Client Hello SNI (OpenSSLSocketImpl): " + hostname);
        this.setHostname(hostname);
    };
} catch(e) {}

try {
    var conSocket = Java.use("com.android.org.conscrypt.AbstractConscryptSocket");
    conSocket.setHostname.implementation = function(hostname) {
        _emit("network.tls", "sni_client_hello", "low",
              "com.android.org.conscrypt.AbstractConscryptSocket", "setHostname",
              { hostname: String(hostname) },
              "TLS Client Hello SNI (AbstractConscryptSocket): " + hostname);
        this.setHostname(hostname);
    };
} catch(e) {}

try {
    var SSLParameters = Java.use("javax.net.ssl.SSLParameters");
    SSLParameters.setServerNames.implementation = function(serverNames) {
        if (serverNames !== null && serverNames.size() > 0) {
            var sniList = [];
            for (var i = 0; i < serverNames.size(); i++) {
                var sni = serverNames.get(i);
                sniList.push(String(sni.toString()));
            }
            _emit("network.tls", "ssl_parameters_sni", "low",
                  "javax.net.ssl.SSLParameters", "setServerNames",
                  { server_names: sniList },
                  "TLS SNI via SSLParameters: " + sniList.join(", "));
        }
        this.setServerNames(serverNames);
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
    
    // Hook all Cipher.init overloads dynamically to cache the opmode parameter
    var initOverloads = _Cipher.init.overloads;
    for (var i = 0; i < initOverloads.length; i++) {
        (function(originalOverload) {
            originalOverload.implementation = function() {
                try {
                    if (arguments.length > 0 && typeof arguments[0] === 'number') {
                        this._opmode_cached = arguments[0];
                    }
                } catch(e) {}
                return originalOverload.apply(this, arguments);
            };
        })(initOverloads[i]);
    }

    _Cipher.doFinal.overload("[B").implementation = function(input) {
        var result = this.doFinal(input);
        var alg    = _trunc(String(this.getAlgorithm()), 60);
        var mode   = -1;
        try {
            if (this._opmode_cached !== undefined) {
                mode = this._opmode_cached;
            } else if (this.opmode !== undefined) {
                mode = this.opmode.value;
            }
        } catch(e2) {}
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
        var mode   = -1;
        try {
            if (this._opmode_cached !== undefined) {
                mode = this._opmode_cached;
            } else if (this.opmode !== undefined) {
                mode = this.opmode.value;
            }
        } catch(e2) {}
        var cat    = (mode === 2) ? "crypto.decrypt" : "crypto.encrypt";
        var action = (mode === 2) ? "decrypt" : "encrypt";
        _emit(cat, action, "medium",
              "javax.crypto.Cipher", "doFinal()",
              { algorithm: alg },
              "Cipher finalize " + action + " using " + alg);
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
_PACK_EVASION = (
    r"""
// ── Evasion detection & spoofing bypass hooks ────────────────────────────────
try {
    var _Dbg = Java.use("android.os.Debug");
    _Dbg.isDebuggerConnected.implementation = function() {
        _emit("anti_debug.signal", "debugger_check", "medium",
              "android.os.Debug", "isDebuggerConnected",
              { result: false },
              "Debugger presence check (bypassed: returned false)");
        return false;
    };
} catch(e) {}

try {
    var _SysProp = Java.use("android.os.SystemProperties");
    
    function bypassSystemProperty(key, originalValue) {
        var k = String(key);
        var val = String(originalValue);
        
        var vmKeys = ["ro.kernel.qemu", "ro.hardware", "ro.product.board", "ro.product.brand", 
                      "ro.product.model", "ro.product.manufacturer", "ro.build.fingerprint", 
                      "ro.secure", "ro.debuggable", "init.svc.goldfish-logcat", "ro.product.device",
                      "ro.board.platform", "ro.boot.hardware"];
                      
        var isVM = vmKeys.some(function(vk) { return k.indexOf(vk) !== -1; });
        if (isVM) {
            var fakeVal = val;
            if (k === "ro.kernel.qemu") fakeVal = "0";
            else if (k === "ro.secure") fakeVal = "1";
            else if (k === "ro.debuggable") fakeVal = "0";
            else if (k === "ro.product.model" || k === "ro.product.device") fakeVal = "SM-G975F";
            else if (k === "ro.product.brand" || k === "ro.product.manufacturer") fakeVal = "samsung";
            else if (k === "ro.build.fingerprint") fakeVal = "samsung/beyond1qlteue/beyond1q:10/QP1A.190711.020/G973U1UES6GVI1:user/release-keys";
            else if (k === "ro.hardware" || k === "ro.boot.hardware" || k === "ro.board.platform") fakeVal = "qcom";
            else if (k.indexOf("goldfish") !== -1) fakeVal = "";
            
            _emit("anti_vm.signal", "property_check", "high",
                  "android.os.SystemProperties", "get",
                  { key: k, value: val, spoofed_value: fakeVal },
                  "VM property check (spoofed): " + k + " (returned: " + fakeVal + ")");
            return fakeVal;
        }
        return originalValue;
    }

    _SysProp.get.overload("java.lang.String").implementation = function(key) {
        var r = this.get(key);
        return bypassSystemProperty(key, r);
    };

    _SysProp.get.overload("java.lang.String", "java.lang.String").implementation = function(key, def) {
        var r = this.get(key, def);
        return bypassSystemProperty(key, r);
    };
} catch(e) {}

try {
    var Build = Java.use("android.os.Build");
    Build.FINGERPRINT.value = "samsung/beyond1qlteue/beyond1q:10/QP1A.190711.020/G973U1UES6GVI1:user/release-keys";
    Build.MODEL.value = "SM-G975F";
    Build.MANUFACTURER.value = "samsung";
    Build.BRAND.value = "samsung";
    Build.DEVICE.value = "beyond1";
    Build.PRODUCT.value = "beyond1q";
    Build.HARDWARE.value = "qcom";
    Build.BOARD.value = "universal9820";
    console.log("[Kavach] android.os.Build static properties spoofed.");
} catch(e) {}

try {
    var ActivityManager = Java.use("android.app.ActivityManager");
    ActivityManager.isUserMonkey.implementation = function() {
        _emit("anti_vm.signal", "monkey_check", "medium", "android.app.ActivityManager", "isUserMonkey", {}, "Monkey UI automation check (bypassed: returned false)");
        return false;
    };
} catch(e) {}

try {
    var File = Java.use("java.io.File");
    
    File.$init.overload("java.lang.String").implementation = function(path) {
        var p = String(path);
        var redirected = p;
        
        var rootPaths = ["/su", "/su/bin/su", "/sbin/su", "/system/bin/su", "/system/xbin/su", 
                         "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su", 
                         "/system/bin/failsafe/su", "/data/local/su", "/system/app/Superuser.apk", 
                         "/system/app/Magisk.apk", "/data/adb/magisk", "bin/su", "xbin/su"];
                         
        var vmPaths = ["/dev/socket/qemud", "/dev/qemu_pipe", "/system/lib/libc_malloc_debug_qemu.so", 
                       "/sys/qemu_trace", "qemu_pipe", "qemud"];
                       
        var fridaPaths = ["frida-server", "re.frida.server", "frida"];

        if (rootPaths.some(function(r) { return p.indexOf(r) !== -1; })) {
            _emit("anti_root.signal", "file_check", "high", "java.io.File", "<init>", { path: p }, "Root file check (bypassed): " + p);
            redirected = "/system/nonexistent_root_file";
        } else if (vmPaths.some(function(v) { return p.indexOf(v) !== -1; })) {
            _emit("anti_vm.signal", "file_check", "high", "java.io.File", "<init>", { path: p }, "VM file check (bypassed): " + p);
            redirected = "/system/nonexistent_vm_file";
        } else if (fridaPaths.some(function(f) { return p.indexOf(f) !== -1; })) {
            _emit("anti_hook.signal", "file_check", "high", "java.io.File", "<init>", { path: p }, "Frida file check (bypassed): " + p);
            redirected = "/system/nonexistent_frida_file";
        }
        
        return this.$init(redirected);
    };

    File.$init.overload("java.io.File", "java.lang.String").implementation = function(parent, child) {
        var c = String(child);
        var redirectedChild = c;
        if (c.indexOf("su") !== -1 || c.indexOf("magisk") !== -1 || c.indexOf("frida") !== -1 || c.indexOf("qemu") !== -1) {
            redirectedChild = "nonexistent_evasion_child";
        }
        return this.$init(parent, redirectedChild);
    };
} catch(e) {}

try {
    var _RTExec = Java.use("java.lang.Runtime");
    _RTExec.exec.overload("java.lang.String").implementation = function(cmd) {
        var c = String(cmd);
        _emit("process.exec", "shell_exec", "high",
              "java.lang.Runtime", "exec",
              { cmd: _trunc(c, 150) },
              "Runtime.exec: " + _trunc(c, 120));
        
        if (c.indexOf("su") !== -1 || c.indexOf("which") !== -1) {
            cmd = "echo 'command not found'";
        }
        return this.exec(cmd);
    };

    _RTExec.exec.overload("[Ljava.lang.String;").implementation = function(cmdArray) {
        var cmdStr = "";
        try {
            var parts = [];
            for (var i = 0; i < cmdArray.length; i++) {
                parts.push(String(cmdArray[i]));
            }
            cmdStr = parts.join(" ");
        } catch(e3) { cmdStr = String(cmdArray); }
        
        _emit("process.exec", "shell_exec", "high",
              "java.lang.Runtime", "exec",
              { cmd: _trunc(cmdStr, 150) },
              "Runtime.exec: " + _trunc(cmdStr, 120));
              
        if (cmdStr.indexOf("su") !== -1 || cmdStr.indexOf("which") !== -1) {
            var JavaString = Java.use("java.lang.String");
            var newArray = [JavaString.$new("echo"), JavaString.$new("command not found")];
            return this.exec(newArray);
        }
        return this.exec(cmdArray);
    };
} catch(e) {}

try {
    var Thread = Java.use("java.lang.Thread");
    Thread.sleep.overload("long").implementation = function(millis) {
        if (millis > 2000) {
            _emit("anti_analysis.timing", "thread_sleep", "medium",
                  "java.lang.Thread", "sleep", { requested_ms: millis },
                  "Timing stall bypassed (requested: " + millis + "ms, fast-forwarded to 50ms)");
            return this.sleep(50);
        }
        return this.sleep(millis);
    };
    Thread.sleep.overload("long", "int").implementation = function(millis, nanos) {
        if (millis > 2000) {
            _emit("anti_analysis.timing", "thread_sleep", "medium",
                  "java.lang.Thread", "sleep", { requested_ms: millis, nanos: nanos },
                  "Timing stall bypassed (requested: " + millis + "ms, fast-forwarded to 50ms)");
            return this.sleep(50, 0);
        }
        return this.sleep(millis, nanos);
    };
} catch(e) {}

try {
    var SystemClock = Java.use("android.os.SystemClock");
    SystemClock.sleep.implementation = function(millis) {
        if (millis > 2000) {
            _emit("anti_analysis.timing", "systemclock_sleep", "medium",
                  "android.os.SystemClock", "sleep", { requested_ms: millis },
                  "SystemClock sleep stall bypassed (requested: " + millis + "ms, fast-forwarded to 50ms)");
            return this.sleep(50);
        }
        return this.sleep(millis);
    };
} catch(e) {}

try {
    var BatteryManager = Java.use("android.os.BatteryManager");
    BatteryManager.getIntProperty.implementation = function(property) {
        var BATTERY_PROPERTY_CAPACITY = 4;
        if (property === BATTERY_PROPERTY_CAPACITY) {
            _emit("anti_analysis.battery", "capacity_check", "medium",
                  "android.os.BatteryManager", "getIntProperty", {},
                  "Battery capacity queried (spoofed to 87%)");
            return 87;
        }
        return this.getIntProperty(property);
    };
} catch(e) {}

// ── Native libc hooks for files and TracerPid ────────────────────────────────
var redirectedStatusPath = "/data/local/tmp/status_spoof";
var redirectedMapsPath = "/data/local/tmp/maps_spoof";
var redirectedTcpPath = "/data/local/tmp/tcp_spoof";

try {
    var File = Java.use("java.io.File");
    var FileInputStream = Java.use("java.io.FileInputStream");
    var FileOutputStream = Java.use("java.io.FileOutputStream");
    var StringBuilder = Java.use("java.lang.StringBuilder");
    var BufferedReader = Java.use("java.io.BufferedReader");
    var InputStreamReader = Java.use("java.io.InputStreamReader");
    var BufferedWriter = Java.use("java.io.BufferedWriter");
    var OutputStreamWriter = Java.use("java.io.OutputStreamWriter");

    // 1. Spoof /proc/self/status (TracerPid: 0)
    var statusFile = File.$new("/proc/self/status");
    if (statusFile.exists()) {
        var br = BufferedReader.$new(InputStreamReader.$new(FileInputStream.$new(statusFile)));
        var outBuilder = StringBuilder.$new();
        var line;
        while ((line = br.readLine()) !== null) {
            var lineStr = String(line);
            if (lineStr.indexOf("TracerPid:") === 0) {
                outBuilder.append("TracerPid:\t0\n");
            } else {
                outBuilder.append(lineStr).append("\n");
            }
        }
        br.close();
        var bw = BufferedWriter.$new(OutputStreamWriter.$new(FileOutputStream.$new(File.$new(redirectedStatusPath))));
        bw.write(outBuilder.toString());
        bw.close();
    }

    // 2. Spoof /proc/self/maps (filter out Frida and gum-js traces)
    var mapsFile = File.$new("/proc/self/maps");
    if (mapsFile.exists()) {
        var br = BufferedReader.$new(InputStreamReader.$new(FileInputStream.$new(mapsFile)));
        var outBuilder = StringBuilder.$new();
        var line;
        while ((line = br.readLine()) !== null) {
            var lineStr = String(line);
            if (lineStr.indexOf("frida") === -1 && lineStr.indexOf("gum-js") === -1 && lineStr.indexOf("re.frida") === -1) {
                outBuilder.append(lineStr).append("\n");
            }
        }
        br.close();
        var bw = BufferedWriter.$new(OutputStreamWriter.$new(FileOutputStream.$new(File.$new(redirectedMapsPath))));
        bw.write(outBuilder.toString());
        bw.close();
    }

    // 3. Spoof /proc/net/tcp (filter out Frida port 27042 -> 69A2 hex)
    var tcpFile = File.$new("/proc/net/tcp");
    if (tcpFile.exists()) {
        var br = BufferedReader.$new(InputStreamReader.$new(FileInputStream.$new(tcpFile)));
        var outBuilder = StringBuilder.$new();
        var line;
        while ((line = br.readLine()) !== null) {
            var lineStr = String(line);
            if (lineStr.indexOf("69A2") === -1 && lineStr.indexOf("58A2") === -1) {
                outBuilder.append(lineStr).append("\n");
            }
        }
        br.close();
        var bw = BufferedWriter.$new(OutputStreamWriter.$new(FileOutputStream.$new(File.$new(redirectedTcpPath))));
        bw.write(outBuilder.toString());
        bw.close();
    }
} catch(e) {
    console.log("Error creating dynamic camouflage files: " + e);
}

try {
    var openPtr = Module.findExportByName(null, "open");
    if (openPtr) {
        Interceptor.attach(openPtr, {
            before: function(args) {
                var path = Memory.readUtf8String(args[0]);
                if (path) {
                    if (path.indexOf("/proc/") !== -1 && path.indexOf("/status") !== -1) {
                        args[0] = Memory.allocUtf8String(redirectedStatusPath);
                    } else if (path.indexOf("/proc/") !== -1 && path.indexOf("/maps") !== -1) {
                        args[0] = Memory.allocUtf8String(redirectedMapsPath);
                    } else if (path.indexOf("/proc/") !== -1 && path.indexOf("/tcp") !== -1) {
                        args[0] = Memory.allocUtf8String(redirectedTcpPath);
                    } else if (path.indexOf("qemu_pipe") !== -1 || path.indexOf("qemud") !== -1) {
                        args[0] = Memory.allocUtf8String("/dev/nonexistent");
                    }
                }
            }
        });
    }
    
    var fopenPtr = Module.findExportByName(null, "fopen");
    if (fopenPtr) {
        Interceptor.attach(fopenPtr, {
            before: function(args) {
                var path = Memory.readUtf8String(args[0]);
                if (path) {
                    if (path.indexOf("/proc/") !== -1 && path.indexOf("/status") !== -1) {
                        args[0] = Memory.allocUtf8String(redirectedStatusPath);
                    } else if (path.indexOf("/proc/") !== -1 && path.indexOf("/maps") !== -1) {
                        args[0] = Memory.allocUtf8String(redirectedMapsPath);
                    } else if (path.indexOf("/proc/") !== -1 && path.indexOf("/tcp") !== -1) {
                        args[0] = Memory.allocUtf8String(redirectedTcpPath);
                    } else if (path.indexOf("qemu_pipe") !== -1 || path.indexOf("qemud") !== -1) {
                        args[0] = Memory.allocUtf8String("/dev/nonexistent");
                    }
                }
            }
        });
    }

    var openatPtr = Module.findExportByName(null, "openat");
    if (openatPtr) {
        Interceptor.attach(openatPtr, {
            before: function(args) {
                var path = Memory.readUtf8String(args[1]);
                if (path) {
                    if (path.indexOf("/proc/") !== -1 && path.indexOf("/status") !== -1) {
                        args[1] = Memory.allocUtf8String(redirectedStatusPath);
                    } else if (path.indexOf("/proc/") !== -1 && path.indexOf("/maps") !== -1) {
                        args[1] = Memory.allocUtf8String(redirectedMapsPath);
                    } else if (path.indexOf("/proc/") !== -1 && path.indexOf("/tcp") !== -1) {
                        args[1] = Memory.allocUtf8String(redirectedTcpPath);
                    } else if (path.indexOf("qemu_pipe") !== -1 || path.indexOf("qemud") !== -1) {
                        args[1] = Memory.allocUtf8String("/dev/nonexistent");
                    }
                }
            }
        });
    }

    var popenPtr = Module.findExportByName(null, "popen");
    if (popenPtr) {
        Interceptor.attach(popenPtr, {
            before: function(args) {
                var command = Memory.readUtf8String(args[0]);
                if (command) {
                    _emit("process.exec", "popen", "high",
                          "libc.so", "popen",
                          { command: String(command) },
                          "Native popen execution: " + command);
                    
                    if (command.indexOf("su") !== -1 || command.indexOf("which") !== -1 || command.indexOf("pm list") !== -1) {
                        args[0] = Memory.allocUtf8String("echo 'not found'");
                    }
                }
            }
        });
    }
} catch(e) {
    console.log("Error installing native open/popen/openat hooks: " + e);
}

try {
    var strcmpPtr = Module.findExportByName(null, "strcmp");
    if (strcmpPtr) {
        Interceptor.attach(strcmpPtr, {
            before: function(args) {
                this.s1 = args[0];
                this.s2 = args[1];
                try {
                    this.str1 = Memory.readUtf8String(this.s1);
                    this.str2 = Memory.readUtf8String(this.s2);
                } catch(e) {
                    this.str1 = null;
                    this.str2 = null;
                }
            },
            onLeave: function(retval) {
                try {
                    if (this.str1 && this.str2) {
                        var hasFrida1 = this.str1.indexOf("frida") !== -1 || this.str1.indexOf("gum-js") !== -1;
                        var hasFrida2 = this.str2.indexOf("frida") !== -1 || this.str2.indexOf("gum-js") !== -1;
                        if (hasFrida1 || hasFrida2) {
                            if (retval.toInt32() === 0) {
                                retval.replace(ptr(-1));
                            }
                        }
                    }
                } catch(e) {}
            }
        });
    }

    var strstrPtr = Module.findExportByName(null, "strstr");
    if (strstrPtr) {
        Interceptor.attach(strstrPtr, {
            before: function(args) {
                this.haystack = args[0];
                this.needle = args[1];
                try {
                    this.str_haystack = Memory.readUtf8String(this.haystack);
                    this.str_needle = Memory.readUtf8String(this.needle);
                } catch(e) {
                    this.str_haystack = null;
                    this.str_needle = null;
                }
            },
            onLeave: function(retval) {
                try {
                    if (this.str_needle && (this.str_needle.indexOf("frida") !== -1 || this.str_needle.indexOf("gum-js") !== -1)) {
                        retval.replace(ptr(0));
                    }
                } catch(e) {}
            }
        });
    }
} catch(e) {
    console.log("Error installing native strcmp/strstr hooks: " + e);
}
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
                var context = null;
                try {
                    var currentApp = Java.use("android.app.ActivityThread").currentApplication();
                    if (currentApp !== null) {
                        context = currentApp.getApplicationContext();
                    }
                } catch(ctxErr) {}
                text = _trunc(String(clip.getItemAt(0).coerceToText(context)), 100);
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
                var context = null;
                try {
                    var currentApp = Java.use("android.app.ActivityThread").currentApplication();
                    if (currentApp !== null) {
                        context = currentApp.getApplicationContext();
                    }
                } catch(ctxErr) {}
                text = _trunc(String(clip.getItemAt(0).coerceToText(context)), 100);
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

_PACK_SSL_UNPINNING = """
// ── Universal SSL Unpinning hook ─────────────────────────────────────────────
try {
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
    var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
    
    var randSuffix = Math.random().toString(36).substring(2, 10);
    
    var TrustManager = Java.registerClass({
        name: "com.kavach.TrustManager_" + randSuffix,
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    // Hook TrustManagerFactory.getTrustManagers
    var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
    TrustManagerFactory.getTrustManagers.implementation = function() {
        return [TrustManager.$new()];
    };
    
    // Hook com.android.org.conscrypt.TrustManagerImpl
    try {
        TrustManagerImpl.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String", "java.lang.String").implementation = function(chain, authType, host) {
            return chain;
        };
        TrustManagerImpl.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String", "java.security.KeyStore").implementation = function(chain, authType, keyStore) {
            return chain;
        };
        TrustManagerImpl.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String", "javax.net.ssl.SSLParameters").implementation = function(chain, authType, params) {
            return chain;
        };
    } catch(e) {}

    // Hook HostnameVerifier
    var DummyHostnameVerifier = Java.registerClass({
        name: "com.kavach.HostnameVerifier_" + randSuffix,
        implements: [HostnameVerifier],
        methods: {
            verify: function(hostname, session) { return true; }
        }
    });
    HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(v) {
        return this.setDefaultHostnameVerifier(DummyHostnameVerifier.$new());
    };

    // Hook OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
            return;
        };
        CertificatePinner.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function(hostname, peerCertificates) {
            return;
        };
    } catch(e) {}
    
    console.log("[Kavach] Universal SSL Unpinning bypass installed.");
} catch(e) {
    console.log("[Kavach] SSL Unpinning installation failed: " + e);
}
"""

_PACK_ACCESSIBILITY = """
// ── Accessibility Service hooks ──────────────────────────────────────────────
try {
    var _AM = Java.use("android.view.accessibility.AccessibilityManager");
    _AM.isEnabled.implementation = function() {
        var r = this.isEnabled();
        _emit("accessibility.abuse", "is_enabled", "medium",
              "android.view.accessibility.AccessibilityManager", "isEnabled",
              { result: r },
              "App checked if AccessibilityManager is enabled (result=" + r + ")");
        return r;
    };
    _AM.getEnabledAccessibilityServiceList.implementation = function(feedbackTypeFlags) {
        var r = this.getEnabledAccessibilityServiceList(feedbackTypeFlags);
        _emit("accessibility.abuse", "get_enabled_services", "high",
              "android.view.accessibility.AccessibilityManager", "getEnabledAccessibilityServiceList",
              {},
              "App queried enabled accessibility services");
        return r;
    };
} catch(e) {}

try {
    var _AS = Java.use("android.accessibilityservice.AccessibilityService");
    _AS.onAccessibilityEvent.implementation = function(event) {
        var eventType = event ? event.getEventType() : -1;
        var packageName = event ? event.getPackageName() : "";
        _emit("accessibility.abuse", "on_accessibility_event", "critical",
              "android.accessibilityservice.AccessibilityService", "onAccessibilityEvent",
              { event_type: eventType, target_package: String(packageName) },
              "AccessibilityService intercepting event from package: " + packageName + " (type=" + eventType + ")");
        this.onAccessibilityEvent(event);
    };
    _AS.getRootInActiveWindow.implementation = function() {
        _emit("accessibility.abuse", "get_root_window", "critical",
              "android.accessibilityservice.AccessibilityService", "getRootInActiveWindow",
              {},
              "AccessibilityService queried root window hierarchy (credential harvesting risk)");
        return this.getRootInActiveWindow();
    };
} catch(e) {}

try {
    var _ANI = Java.use("android.view.accessibility.AccessibilityNodeInfo");
    _ANI.performAction.overload("int").implementation = function(action) {
        _emit("accessibility.abuse", "perform_node_action", "critical",
              "android.view.accessibility.AccessibilityNodeInfo", "performAction",
              { action: action },
              "AccessibilityNodeInfo simulated action execution: action=" + action);
        return this.performAction(action);
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
    "ssl_unpinning":   _PACK_SSL_UNPINNING,
    "accessibility":   _PACK_ACCESSIBILITY,
}

# Core packs always loaded — lightweight, high signal
DEFAULT_PACKS: List[str] = [
    "shared_prefs", "network", "crypto", "native", "clipboard", "permissions",
    "sms_telephony", "location_gps", "media_recorder", "dynamic_loading", "process_builder", "app_listing", "ssl_unpinning", "accessibility"
]


def build_frida_script(active_packs: List[str]) -> str:
    """
    Assemble a single Java.perform Frida script from the requested hook packs.
    Unknown pack names are silently skipped.
    """
    selected = [p for p in active_packs if p in ALL_PACKS]
    packs_js = "\n\n".join(ALL_PACKS[p] for p in selected)
    packs_label = ", ".join(selected)

    return f"""\
// Kavach Frida Hook Script — Packs: {packs_label}
// Guard: poll for ART/Dalvik VM readiness via setInterval (works on Android 11 x86_64 APEX)
(function kavachMain() {{
    var MAX_RETRIES = 60;
    var attempts = 0;
    var intervalId = null;

    function tryInstall() {{
        attempts++;
        // On Android 11 x86_64 APEX, Java global is bound AFTER script top-level runs.
        // We use setInterval so our check runs after the Frida agent finishes initializing.
        var javaReady = (typeof Java !== 'undefined') && Java.available;
        if (!javaReady) {{
            if (attempts >= MAX_RETRIES) {{
                clearInterval(intervalId);
                console.error('[Kavach] Java bridge unavailable after ' + attempts + ' attempts (Android 11 x86_64 APEX incompatibility).');
            }}
            return;
        }}
        clearInterval(intervalId);
        console.log('[Kavach] Java bridge ready after ' + attempts + ' poll attempt(s).');
        Java.perform(function() {{
            console.log('[Kavach] Instrumentation active. Packs: {packs_label}');

{_HELPER_JS}

{packs_js}

            console.log('[Kavach] All hook packs installed.');
        }});
    }}

    // Use setInterval so the check runs after the Frida agent fully initializes globals
    intervalId = setInterval(tryInstall, 300);
    // Also fire immediately in case Java is already available (spawned + resumed case)
    tryInstall();
}})();
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
    if static_signals.get("has_accessibility"):
        packs.append("accessibility")

    # Deduplicate preserving insertion order
    seen = set()
    result = []
    for p in packs:
        if p not in seen:
            seen.add(p)
            result.append(p)
    return result
