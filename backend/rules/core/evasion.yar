rule Evasion_Tactics {
    meta:
        author = "KAVACH AI"
        date = "2026-06-23"
        malware_family = "android_evasion"
        severity = "HIGH"
        mitre_technique = "T1622"
        reference_sample_sha256 = "c18a23bb8006e8bfa6b677a288924bcf8e09f8749a2123ef61db6c1097fa620e"
        fp_notes = "Detects debugger and root indicators. May trigger on legitimate banking/finance apps that employ security checks to prevent tampering."
        description = "Detects emulator detection, root checks, and debugger detection code structures"
        reference = "https://attack.mitre.org/techniques/T1622/"

    strings:
        // Emulator properties check
        $emu1 = "ro.build.fingerprint" ascii nocase
        $emu2 = "ro.product.model" ascii nocase
        $emu3 = "ro.hardware" ascii nocase
        $emu4 = "goldfish" ascii nocase
        $emu5 = "qemu" ascii nocase
        $emu6 = "sdk_gphone" ascii nocase

        // Debugger check APIs
        $dbg1 = "isDebuggerConnected" ascii
        $dbg2 = "Debug.isDebuggerConnected" ascii

        // Root signatures check
        $root1 = "/system/app/Superuser.apk" ascii nocase
        $root2 = "/system/xbin/su" ascii nocase
        $root3 = "which su" ascii nocase
    condition:
        (3 of ($emu*)) or ($dbg1 or $dbg2) or (2 of ($root*))
}
