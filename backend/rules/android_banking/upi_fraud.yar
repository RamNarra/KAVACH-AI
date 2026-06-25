rule UPI_Phishing_Fraud {
    meta:
        author = "KAVACH AI"
        date = "2026-06-23"
        malware_family = "android_banking.upi_fraud"
        severity = "CRITICAL"
        mitre_technique = "T1411"
        reference_sample_sha256 = "f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9"
        fp_notes = "Detects UPI intent manipulation and Indian fintech overlay phishing attempts. Excludes standard payment gateways such as Razorpay, PayUMoney, and JioMoney integrations."
        description = "Detects UPI intent hijacking, BHIM/phishing strings, or overlay keywords for Indian banks"
        reference = "https://attack.mitre.org/techniques/T1411/"

    strings:
        // UPI deep link schemes
        $upi_scheme1 = "upi://pay" ascii nocase
        $upi_scheme2 = "upi://collect" ascii nocase
        
        // UPI components / packages
        $pkg_phonepe = "com.phonepe.app" ascii nocase
        $pkg_gpay = "com.google.android.apps.nbu.paisa.user" ascii nocase
        $pkg_paytm = "net.one97.paytm" ascii nocase
        $pkg_bhim = "com.bhimupi.bhim" ascii nocase

        // Indian Banking / UPI Phishing keywords
        $phish1 = "UPI PIN" ascii nocase
        $phish2 = "Enter UPI PIN" ascii nocase
        $phish3 = "Verify PAN Card" ascii nocase
        $phish4 = "Limit Exceeded" ascii nocase
        $phish5 = "KYC Verification" ascii nocase
        $phish6 = "account blocked" ascii nocase

        // False Positive Suppression
        $fp_legit_sdk1 = "Razorpay" ascii nocase
        $fp_legit_sdk2 = "PayUMoney" ascii nocase
        $fp_legit_sdk3 = "JioMoney" ascii nocase
        $fp_legit_sdk4 = "upi.integration" ascii nocase
    condition:
        (
            (any of ($upi_scheme*) and 2 of ($phish*)) or
            (2 of ($pkg_*) and 2 of ($phish*)) or
            (any of ($upi_scheme*) and any of ($pkg_*) and any of ($phish*))
        )
        and not (any of ($fp_legit_*))
}
