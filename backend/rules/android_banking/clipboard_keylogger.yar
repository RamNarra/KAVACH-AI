rule Clipboard_Keylogger_Trojan {
    meta:
        author = "KAVACH AI"
        date = "2026-06-23"
        malware_family = "android_banking.keylogger"
        severity = "HIGH"
        mitre_technique = "T1636.001"
        reference_sample_sha256 = "c5c6e8e89f8f4a7a8a6b6c6d6e6f7a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f"
        fp_notes = "Detects clipboard hijacking and keylogger event hooks. Excludes standard copy/paste widgets, UPI code copy helpers, and typical custom input PIN view handlers."
        description = "Detects clipboard hijacking and keylogger event handlers"
        reference = "https://attack.mitre.org/techniques/T1636/001/"

    strings:
        // Clipboard listener APIs
        $clip1 = "ClipboardManager" ascii
        $clip2 = "addPrimaryClipChangedListener" ascii
        $clip3 = "getPrimaryClip" ascii
        $clip4 = "setPrimaryClip" ascii

        // Keylogging Event hooks
        $key1 = "dispatchKeyEvent" ascii
        $key2 = "onKeyDown" ascii
        $key3 = "onKeyUp" ascii
        $key4 = "KeyEvent.KEYCODE_" ascii
        
        // Log identifiers common in keyloggers
        $log1 = "clipboard_monitor" ascii nocase
        $log2 = "keylogger" ascii nocase
        $log3 = "typed_chars" ascii nocase

        // False Positive Suppression
        $fp_legit_sdk1 = "copyToClipboard" ascii nocase
        $fp_legit_sdk2 = "ClipboardHelper" ascii nocase
        $fp_legit_sdk3 = "CouponCode" ascii nocase
        $fp_legit_sdk4 = "PinView" ascii nocase
    condition:
        (
            (all of ($clip*)) or 
            (2 of ($key*) and any of ($clip*)) or 
            (any of ($log*))
        )
        and not (any of ($fp_legit_*))
}
