rule SMS_Stealer {
    meta:
        author = "KAVACH AI"
        date = "2026-06-23"
        malware_family = "android_banking.sms_intercept"
        severity = "HIGH"
        mitre_technique = "T1636.002"
        reference_sample_sha256 = "dbb883017cfbf68d2f23cfb8dbb83017cfbf68d2f23cfb8dbb83017cfbf68d2f"
        fp_notes = "Detects broad SMS read/receive actions. Excludes standard Google Play Services SmsRetriever API and Firebase Auth to prevent flagging legitimate OTP retrieval."
        description = "Detects Android banking malware SMS interception and OTP stealing capability"
        reference = "https://attack.mitre.org/techniques/T1636/002/"

    strings:
        // SMS Permissions
        $perm1 = "android.permission.RECEIVE_SMS" ascii nocase
        $perm2 = "android.permission.READ_SMS" ascii nocase
        $perm3 = "android.permission.SEND_SMS" ascii nocase

        // Android SMS APIs & Actions
        $action_received = "android.provider.Telephony.SMS_RECEIVED" ascii nocase
        $api_sms_manager = "SmsManager" ascii
        $api_get_messages = "getMessagesFromIntent" ascii
        $api_pdus = "pdus" ascii
        $api_pdu_create = "createFromPdu" ascii

        // Suspicious keywords or log tags
        $log_tag1 = "SMSListener" ascii nocase
        $log_tag2 = "OTPIntercept" ascii nocase
        $log_tag3 = "SmsReceiver" ascii nocase

        // False Positive Suppression
        $fp_legit_sdk1 = "SmsRetriever" ascii nocase
        $fp_legit_sdk2 = "com.google.android.gms.auth" ascii nocase
        $fp_legit_sdk3 = "FirebaseAuth" ascii nocase
    condition:
        (
            (all of ($perm*)) or 
            (any of ($perm*) and ($action_received or $api_get_messages or $api_pdus or $api_sms_manager or $api_pdu_create)) or 
            (2 of ($log_tag*))
        )
        and not (any of ($fp_legit_*))
}
