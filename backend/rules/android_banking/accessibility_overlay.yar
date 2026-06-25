rule Overlay_Attack {
    meta:
        author = "KAVACH AI"
        date = "2026-06-23"
        malware_family = "android_banking.accessibility_overlay"
        severity = "CRITICAL"
        mitre_technique = "T1411"
        reference_sample_sha256 = "b78b8719f9bb49f28e20de63b78c2e63b78c2e63b78c2e63b78c2e63b78c2e63"
        fp_notes = "Detects accessibility service abuse and screen overlay drawing. Excludes common clean floating tools, messenger chat heads, and system maps overlays."
        description = "Detects accessibility service abuse and screen overlay drawing used in banking trojans"
        reference = "https://attack.mitre.org/techniques/T1411/"

    strings:
        // Dangerous permissions/actions
        $perm_overlay = "android.permission.SYSTEM_ALERT_WINDOW" ascii nocase
        $action_accessibility = "android.accessibilityservice.AccessibilityService" ascii nocase
        $bind_accessibility = "android.permission.BIND_ACCESSIBILITY_SERVICE" ascii nocase

        // Window overlay flags
        $overlay_type1 = "TYPE_APPLICATION_OVERLAY" ascii
        $overlay_type2 = "LayoutParams.FLAG_NOT_TOUCH_MODAL" ascii
        $overlay_type3 = "LayoutParams.FLAG_NOT_FOCUSABLE" ascii

        // Accessibility methods & event types
        $event_window_changed = "TYPE_WINDOW_CONTENT_CHANGED" ascii
        $event_state_changed = "TYPE_WINDOW_STATE_CHANGED" ascii
        $api_accessibility_node = "AccessibilityNodeInfo" ascii
        $api_perform_action = "performAction" ascii

        // Common overlay drawing patterns
        $draw_overlay = "canDrawOverlays" ascii
        $add_view = "addView" ascii

        // False Positive Suppression
        $fp_legit_sdk1 = "facebook.messenger" ascii nocase
        $fp_legit_sdk2 = "map.navigation" ascii nocase
        $fp_legit_sdk3 = "FloatView" ascii nocase
        $fp_legit_sdk4 = "FloatingService" ascii nocase
    condition:
        (
            ($bind_accessibility and ($event_window_changed or $api_accessibility_node or $api_perform_action)) or
            ($perm_overlay and ($add_view or $draw_overlay) and ($overlay_type1 or $overlay_type2 or $overlay_type3)) or
            ($action_accessibility and 2 of ($overlay_type*, $event_*))
        )
        and not (any of ($fp_legit_*))
}
