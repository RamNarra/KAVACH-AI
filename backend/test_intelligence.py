"""Tests for banking fraud, risk engine, and ATT&CK mapping."""

from banking_fraud import analyze_banking_fraud
from attack_mapping import map_evidence_to_attack
from risk_engine import build_risk_decomposition, derive_dynamic_score


MANIFEST_SMS = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <uses-permission android:name="android.permission.RECEIVE_SMS"/>
  <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
</manifest>"""


def test_banking_fraud_detects_sms_and_overlay():
    result = analyze_banking_fraud(MANIFEST_SMS, {}, [], [])
    ids = {b["id"] for b in result["badges"]}
    assert "BANK-SMS-STEALER" in ids
    assert "BANK-OVERLAY" in ids
    assert result["fraud_score"] > 0


def test_attack_mapping_from_permissions():
    evidence = {"permissions": [{"name": "android.permission.RECEIVE_SMS"}]}
    techniques = map_evidence_to_attack(evidence, [])
    assert any(t["id"] == "T1636.001" for t in techniques)


def test_risk_decomposition():
    dec = build_risk_decomposition(60, 40, 70, 50)
    assert dec["composite_score"] > 0
    assert "static" in dec["components"]


def test_dynamic_score_zero_when_unavailable():
    assert derive_dynamic_score([], 0, "UNAVAILABLE") == 0


def test_zipbomb_prevention_on_download():
    import tempfile
    import os
    import zipfile
    import io
    import pytest
    from main import _write_downloaded_apk

    with tempfile.TemporaryDirectory() as tmpdir:
        fake_apk = os.path.join(tmpdir, "test_bomb.apk")
        
        # Create a tiny zip with fake metadata claiming 2.5GB uncompressed
        zinfo = zipfile.ZipInfo("fake.txt")
        zinfo.file_size = 2500 * 1024 * 1024
        zinfo.compress_size = 4
        
        # Write it to raw bytes
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            zf.writestr(zinfo, b"tiny")
            zf.filelist[0].file_size = 2500 * 1024 * 1024
        raw_bytes = zip_buffer.getvalue()
        
        # Run _write_downloaded_apk and expect Exception
        with pytest.raises(Exception) as excinfo:
            _write_downloaded_apk(raw_bytes, fake_apk)
        
        assert "Possible zipbomb" in str(excinfo.value)
        assert not os.path.exists(fake_apk)


def test_rate_limiter():
    from routes import InMemRateLimiter
    limiter = InMemRateLimiter(2, 60)
    assert limiter.check("ip1") is True
    assert limiter.check("ip1") is True
    assert limiter.check("ip1") is False  # 3rd time within 60s is blocked
    assert limiter.check("ip2") is True  # other key/IP is not blocked


def test_calculate_deterministic_score_fast_scan():
    from analysis_engine import calculate_deterministic_score
    # Dummy manifest with SEND_SMS permission
    manifest = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android">
      <uses-permission android:name="android.permission.SEND_SMS"/>
    </manifest>"""
    res = calculate_deterministic_score(
        manifest_content=manifest,
        jadx_sources={},
        androguard_res={
            "suspicious_strings": [{"type": "Hardcoded IP URL", "value": "http://1.2.3.4", "risk_score": 15}],
            "dangerous_api_chains": [{"type": "IMEI Exfiltration via SMS", "risk_score": 25}],
            "risky_classes": [],
            "score": 40
        },
        apkid_json_path=None,
        quark_json_path=None,
        apktool_out=None,
        jadx_out=None,
        apk_path=None,
    )
    assert res["risk_score"] > 0
    assert len(res["evidence"]["permissions"]) == 1
    # SEND_SMS is a dangerous permission, which is recorded in exposure/permissions
    assert res["evidence"]["permissions"][0]["name"] == "android.permission.SEND_SMS"
    # Verification of Androguard DEX findings propagation
    assert len(res["evidence"]["reflection_dynamic_loading"]) == 1
    assert res["evidence"]["reflection_dynamic_loading"][0]["type"] == "IMEI Exfiltration via SMS"


def test_select_key_java_files_casing_and_segments():
    import tempfile
    import os
    from main import select_key_java_files

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a sources directory structure simulating decompiled output
        # Package: com.bankofindia.shield (3 segments base: com.bankofindia)
        # We'll create:
        # 1. A com.bankofindia.shield.MainActivity (matching package path)
        # 2. A com.BankOfIndia.shield.FraudService (matching case-insensitively)
        # 3. A com.google.Library (should be pruned)
        
        sources_dir = os.path.join(tmpdir, "sources")
        os.makedirs(os.path.join(sources_dir, "com", "bankofindia", "shield"), exist_ok=True)
        os.makedirs(os.path.join(sources_dir, "com", "BankOfIndia", "helper"), exist_ok=True)
        os.makedirs(os.path.join(sources_dir, "com", "google", "library"), exist_ok=True)

        main_activity_path = os.path.join(sources_dir, "com", "bankofindia", "shield", "MainActivity.java")
        with open(main_activity_path, "w") as f:
            f.write("class MainActivity { // http url connection\n}")

        fraud_service_path = os.path.join(sources_dir, "com", "BankOfIndia", "helper", "FraudService.java")
        with open(fraud_service_path, "w") as f:
            f.write("class FraudService { // runtime exec loadlibrary\n}")

        google_lib_path = os.path.join(sources_dir, "com", "google", "library", "GoogleLib.java")
        with open(google_lib_path, "w") as f:
            f.write("class GoogleLib { // http url connection\n}")

        # Run select_key_java_files with package "com.bankofindia.shield" (which has base "com.bankofindia")
        key_files, all_paths = select_key_java_files(tmpdir, "com.bankofindia.shield")
        
        # Verify the helper under BankOfIndia (case mismatch) and MainActivity are selected, but GoogleLib is excluded or pruned
        # GoogleLib matches com/google/ which is pruned in rel_path loops
        assert any("MainActivity.java" in k for k in key_files)
        assert any("FraudService.java" in k for k in key_files)
        assert not any("GoogleLib.java" in k for k in key_files)


def test_composite_score_conservative_aggregation():
    from risk_engine import build_risk_decomposition
    
    # Case 1: Static is 100, dynamic is 56. Conservative aggregation must yield 100.
    res1 = build_risk_decomposition(
        static_score=100,
        dynamic_score=56,
        ai_score=0,
        fraud_score=0
    )
    assert res1["composite_score"] == 100

    # Case 2: Static is 20, dynamic is 95. Conservative aggregation must yield 95.
    res2 = build_risk_decomposition(
        static_score=20,
        dynamic_score=95,
        ai_score=0,
        fraud_score=0
    )
    assert res2["composite_score"] == 95

    # Case 3: Static is 30, dynamic is 40, fraud is 85. Composite must yield 85.
    res3 = build_risk_decomposition(
        static_score=30,
        dynamic_score=40,
        ai_score=0,
        fraud_score=85
    )
    assert res3["composite_score"] == 85


def test_banking_fraud_comment_stripping():
    # If a signature matches only in a comment, it should not trigger the Trojan match
    # BRATA signature: "brata"
    # We construct sources with a comment containing "brata"
    sources = {"Test.java": "public class Test { // matches brata pattern\n }"}
    # The BFL calculation requires OVERLAY_PERMS or similar to exceed 5.0, so let's check BFL first.
    # If BFL is < 5.0, family checks are skipped. Let's make BFL >= 5.0 by providing SMS and overlay permissions.
    manifest_brata = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android">
      <uses-permission android:name="android.permission.RECEIVE_SMS"/>
      <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
    </manifest>"""
    
    result = analyze_banking_fraud(manifest_brata, sources, [], [], "com.safe.app", "safe.apk")
    ids = {b["id"] for b in result["badges"]}
    assert "BANK-TROJAN-FINGERPRINT" not in ids


def test_exfiltration_badge_refinement():
    # If a URL contains a keyword but there's no sensitive data exfiltrated, it should NOT trigger BANK-CRED-EXFIL
    safe_event = {
        "category": "network.http",
        "evidence": "Contacting https://bankofindia.com/api/v1/status",
        "args": {}
    }
    result_safe = analyze_banking_fraud("", {}, [safe_event], [])
    ids_safe = {b["id"] for b in result_safe["badges"]}
    assert "BANK-CRED-EXFIL" not in ids_safe

    # If it is a network event AND there is sensitive data in args/payload, it SHOULD trigger
    unsafe_event = {
        "category": "network.http",
        "evidence": "Posting to https://malicious-server.com/collect",
        "args": {"otp": "123456"}
    }
    result_unsafe = analyze_banking_fraud("", {}, [unsafe_event], [])
    ids_unsafe = {b["id"] for b in result_unsafe["badges"]}
    assert "BANK-CRED-EXFIL" in ids_unsafe


def test_new_mitre_attack_mappings():
    # Test that asymmetric crypto (RSA) maps to T1521.002
    evidence = {
        "crypto_issues": [{"type": "RSA Key Generation", "description": "RSA key generated with 2048 bits"}]
    }
    techniques = map_evidence_to_attack(evidence, [])
    assert any(t["id"] == "T1521.002" for t in techniques)

    # Test that alarm manager maps to T1603
    evidence_alarm = {
        "reflection_dynamic_loading": [{"type": "AlarmManager usage", "description": "AlarmManager used"}]
    }
    techniques_alarm = map_evidence_to_attack(evidence_alarm, [])
    assert any(t["id"] == "T1603" for t in techniques_alarm)


def test_manifest_xml_comment_exclusion():
    # If the family signature is only present in a manifest XML comment, it should be stripped
    manifest_comment = """<?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android">
      <uses-permission android:name="android.permission.RECEIVE_SMS"/>
      <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
      <!-- This app matches brata pattern comment -->
    </manifest>"""
    
    result = analyze_banking_fraud(manifest_comment, {}, [], [], "com.safe.app", "safe.apk")
    ids = {b["id"] for b in result["badges"]}
    assert "BANK-TROJAN-FINGERPRINT" not in ids


def test_gemini_json_cleaning_and_parsing():
    from main import clean_and_parse_json
    raw_markdown = "Some chat introduction... ```json\n{\n  \"risk_score\": 75,\n  \"threat_level\": \"HIGH\"\n}\n``` Some ending."
    parsed = clean_and_parse_json(raw_markdown)
    assert parsed.get("risk_score") == 75
    assert parsed.get("threat_level") == "HIGH"


def test_kavach_demo_mode_fallback():
    import os
    from dynamic_engine import run_behavioral_trace
    os.environ["KAVACH_DEMO_MODE"] = "1"
    try:
        res = run_behavioral_trace("dummy.apk", "com.dummy.app", duration=20)
        assert res["status"] == "COMPLETED"
        assert res["event_count"] == 6
        assert any(e["category"] == "window.overlay" for e in res["normalized_events"])
        assert any(e["category"] == "telephony.sms" for e in res["normalized_events"])
    finally:
        del os.environ["KAVACH_DEMO_MODE"]


def test_ai_cross_validation():
    from main import _cross_validate_ai_findings
    
    ir_dict = {
        "suspicious_activities": [
            {"title": "SMS Interceptor message", "description": "Reads SMS messages", "file": "SmsReceiver.java"},
            {"title": "Unrelated Suspicious Thing", "description": "Some weird function", "file": "Unknown.java"}
        ],
        "code_vulnerabilities": [
            {"title": "Insecure Crypto Key Use", "description": "Uses hardcoded KeySpec", "file": "CryptoHelper.java"}
        ]
    }
    
    deterministic_evidence = {
        "evidence": {
            "sms_issues": [{"title": "SMS Interceptor", "description": "Intercepts SMS messages"}],
            "crypto_issues": [{"title": "Hardcoded KeySpec", "file": "CryptoHelper.java"}]
        }
    }
    
    updated = _cross_validate_ai_findings(ir_dict, deterministic_evidence)
    
    activities = updated["suspicious_activities"]
    assert activities[0]["evidence_source"] == "confirmed"
    assert activities[1]["evidence_source"] == "ai_only"
    
    vulns = updated["code_vulnerabilities"]
    assert vulns[0]["evidence_source"] == "confirmed"


def test_vision_guided_play_static_context():
    from playbook_engine import _step_vision_guided_play
    import playbook_engine
    
    # Mock GenAI client to capture the prompt
    captured_prompts = []
    
    class MockGenerateResponse:
        def __init__(self):
            self.text = '{"screen_type": "permission", "action": "click", "target_x_percent": 50.0, "target_y_percent": 85.0, "explanation": "accept perm"}'

    class MockModels:
        def generate_content(self, model, contents, config=None, *args, **kwargs):
            # contents can be [img, prompt]
            prompt = contents[1]
            captured_prompts.append(prompt)
            return MockGenerateResponse()

    class MockClient:
        def __init__(self):
            self.models = MockModels()

    # Monkeypatch client getter
    original_getter = playbook_engine._get_genai_client
    playbook_engine._get_genai_client = lambda: MockClient()

    # Mock _run to return success for screen size check and screencap
    original_run = playbook_engine._run
    def mock_run(args, **kwargs):
        class MockCompletedProcess:
            def __init__(self, args, returncode, stdout, stderr):
                self.args = args
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr
        if len(args) > 2 and "wm" in args and "size" in args:
            return MockCompletedProcess(args, 0, "Physical size: 1080x1920", "")
        if len(args) > 2 and "screencap" in args:
            return MockCompletedProcess(args, 0, "", "")
        if len(args) > 3 and "pull" in args:
            # We need to create a dummy image locally
            local_path = args[3]
            from PIL import Image
            img = Image.new("RGB", (100, 100), color="red")
            img.save(local_path)
            return MockCompletedProcess(args, 0, "", "")
        return MockCompletedProcess(args, 0, "", "")

    playbook_engine._run = mock_run

    try:
        import tempfile
        transcript = []
        static_signals = {
            "has_anti_vm": True,
            "has_login_fields": True,
            "static_evidence": {
                "permissions": ["android.permission.RECEIVE_SMS", "android.permission.READ_PHONE_STATE"],
                "malware_rule_hits": [{"rule_name": "RansomwareBehavior"}, "BankingTrojanInfo"],
                "suspicious_urls": [{"url": "http://evil-c2.com/exfil"}],
                "network_indicators": ["evil-c2.com"]
            }
        }
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            _step_vision_guided_play(
                adb="dummy_adb",
                tmp_dir=tmp_dir,
                transcript=transcript,
                static_signals=static_signals,
                max_steps=1
            )
            
        assert len(captured_prompts) > 0
        prompt = captured_prompts[0]
        assert "RECEIVE_SMS" in prompt
        assert "RansomwareBehavior" in prompt
        assert "evil-c2.com" in prompt
        assert "CONTEXT FROM STATIC ANALYSIS" in prompt
        assert "INSTRUCTION FOR PLAYBOOK NAVIGATION" in prompt
        
    finally:
        playbook_engine._get_genai_client = original_getter
        playbook_engine._run = original_run








