rule apk_magic {
    meta:
        author = "KAVACH AI"
        date = "2026-06-23"
        malware_family = "core.file_format"
        severity = "INFO"
        mitre_technique = "N/A"
        reference_sample_sha256 = "N/A"
        fp_notes = "Detects standard Android archive format headers. Legitimate applications are expected to hit this rule."
        description = "Detects Android DEX executable or standard APK/ZIP archive format"
        reference = "https://source.android.com/docs/core/ota/sign-builds"

    strings:
        // PK ZIP Magic header (commonly used for APKs)
        $zip_magic = { 50 4b 03 04 }
        
        // DEX executable magic header
        $dex_magic = { 64 65 78 0a 30 33 } // dex\n03
    condition:
        $zip_magic at 0 or $dex_magic at 0
}
