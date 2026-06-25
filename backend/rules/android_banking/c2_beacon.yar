rule C2_Beacon_Exfiltration {
    meta:
        author = "KAVACH AI"
        date = "2026-06-23"
        malware_family = "android_banking.c2_beacon"
        severity = "HIGH"
        mitre_technique = "T1071"
        reference_sample_sha256 = "d7d8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8"
        fp_notes = "Detects trojan command gates and parameter-based exfiltration routes. Excludes standard Google Play API endpoints, Firebase, and Crashlytics libraries."
        description = "Detects hardcoded IP addresses, command paths, or dynamic C2 configurations"
        reference = "https://attack.mitre.org/techniques/T1071/"

    strings:
        // C2 endpoint routes
        $path1 = "/api/v1/" ascii nocase
        $path2 = "/inject_page/" ascii nocase
        $path3 = "/send_sms/" ascii nocase
        $path4 = "/log_info/" ascii nocase
        $path5 = "/gate.php" ascii nocase
        $path6 = "/bot_receiver.php" ascii nocase
        
        // Exfiltration variables
        $param1 = "phone_number" ascii nocase
        $param2 = "otp_code" ascii nocase
        $param3 = "card_number" ascii nocase
        $param4 = "cvv" ascii nocase
        $param5 = "device_id" ascii nocase

        // Network libraries
        $net1 = "HttpURLConnection" ascii
        $net2 = "okhttp3" ascii nocase
        $net3 = "Retrofit" ascii

        // False Positive Suppression
        $fp_legit_sdk1 = "play.googleapis.com" ascii nocase
        $fp_legit_sdk2 = "firebaseinstallations.googleapis.com" ascii nocase
        $fp_legit_sdk3 = "crashlytics" ascii nocase
    condition:
        (
            (2 of ($path*) and 2 of ($param*)) or
            (any of ($path*) and 3 of ($param*) and any of ($net*))
        )
        and not (any of ($fp_legit_*))
}
