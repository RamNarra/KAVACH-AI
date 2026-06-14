"""Tests for banking fraud, risk engine, and ATT&CK mapping."""

from banking_fraud import analyze_banking_fraud
from attack_mapping import map_evidence_to_attack
from risk_engine import build_risk_decomposition, derive_dynamic_score
import threading
import uuid
from supabase_db import ArrayUnion as SupabaseArrayUnion, Query as SupabaseQuery

class MockSnapshot:
    def __init__(self, doc_id, data):
        self.id = doc_id
        self._data = data
        self.exists = data is not None
    def to_dict(self):
        return dict(self._data) if self._data else {}

class MockDocRef:
    def __init__(self, col, doc_id, storage, lock):
        self.col = col
        self.id = doc_id
        self.storage = storage
        self.lock = lock
        self.key = f"{col}/{doc_id}"
    def get(self):
        with self.lock:
            return MockSnapshot(self.id, self.storage.get(self.key))
    def set(self, data):
        with self.lock:
            self.storage[self.key] = data
    def delete(self):
        with self.lock:
            if self.key in self.storage:
                del self.storage[self.key]
    def update(self, updates):
        with self.lock:
            data = self.storage.setdefault(self.key, {})
            for k, v in updates.items():
                if hasattr(v, "values"):
                    data[k] = data.get(k, []) + v.values
                else:
                    data[k] = v
    def check_and_update_rate_limit(self, now, window_secs, requests_limit):
        with self.lock:
            data = self.storage.setdefault(self.key, {})
            timestamps = data.get("timestamps", [])
            if not isinstance(timestamps, list):
                timestamps = []
            timestamps = [t for t in timestamps if now - t < window_secs]
            if len(timestamps) >= requests_limit:
                return False
            timestamps.append(now)
            data["timestamps"] = timestamps
            return True

class MockColRef:
    def __init__(self, name, storage, lock):
        self.name = name
        self.storage = storage
        self.lock = lock
    def document(self, doc_id=None):
        if doc_id is None:
            doc_id = uuid.uuid4().hex
        return MockDocRef(self.name, doc_id, self.storage, self.lock)

class MockDB:
    ArrayUnion = SupabaseArrayUnion
    Query = SupabaseQuery
    def __init__(self):
        self.storage = {}
        self.lock = threading.Lock()
    def collection(self, name):
        return MockColRef(name, self.storage, self.lock)




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
    import routes
    if routes.db is not None:
        try:
            routes.db.collection("rate_limit_default").document("ip1").delete()
            routes.db.collection("rate_limit_default").document("ip2").delete()
        except Exception:
            pass
    limiter = routes.InMemRateLimiter(2, 60)
    assert limiter.check("ip1") is True
    assert limiter.check("ip1") is True
    assert limiter.check("ip1") is False  # 3rd time within 60s is blocked
    assert limiter.check("ip2") is True  # other key/IP is not blocked


def test_rate_limiter_db_fallback():
    import routes
    original_db = routes.db
    routes.db = MockDB()
    try:
        limiter = routes.HybridRateLimiter("test_db_rate_limiter", 2, 60)
        # Clear database records if any
        routes.db.collection("rate_limit_test_db_rate_limiter").document("ip1").delete()
        routes.db.collection("rate_limit_test_db_rate_limiter").document("ip2").delete()

        assert limiter.check("ip1") is True
        assert limiter.check("ip1") is True
        assert limiter.check("ip1") is False  # Blocked by DB rate limiter
        assert limiter.check("ip2") is True
    finally:
        routes.db = original_db


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
                "permissions": ["android.permission.RECEIVE_SMS", {"name": "android.permission.READ_PHONE_STATE"}, {"permission": "android.permission.RECORD_AUDIO"}],
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
        assert "READ_PHONE_STATE" in prompt
        assert "RECORD_AUDIO" in prompt
        assert "RansomwareBehavior" in prompt
        assert "evil-c2.com" in prompt
        assert "CONTEXT FROM STATIC ANALYSIS" in prompt
        assert "INSTRUCTION FOR PLAYBOOK NAVIGATION" in prompt
        
    finally:
        playbook_engine._get_genai_client = original_getter
        playbook_engine._run = original_run


def test_sandbox_runner_path_separation():
    import pytest
    from sandbox_runner import sandboxed_run, sandboxed_popen
    import os
    
    # Enable sandboxing temporarily
    import sandbox_runner
    original_enabled = sandbox_runner.DOCKER_SANDBOX_ENABLED
    sandbox_runner.DOCKER_SANDBOX_ENABLED = True
    try:
        # Same path should raise ValueError
        with pytest.raises(ValueError) as exc:
            sandboxed_run(["echo"], input_path="/tmp/same", output_path="/tmp/same")
        assert "must be separate directories" in str(exc.value)

        with pytest.raises(ValueError) as exc:
            sandboxed_popen(["echo"], input_path="/tmp/same", output_path="/tmp/same")
        assert "must be separate directories" in str(exc.value)
    finally:
        sandbox_runner.DOCKER_SANDBOX_ENABLED = original_enabled


def test_supabase_db_mocked():
    from unittest.mock import patch, Mock
    import os
    import pytest
    from supabase_db import SupabaseDB, ArrayUnion
    
    # Temporarily set credentials
    os.environ["SUPABASE_URL"] = "https://mock.supabase.co"
    os.environ["SUPABASE_KEY"] = "mock_key"
    
    try:
        db = SupabaseDB()
        doc_ref = db.collection("scans").document("test_doc")
        
        # Test get()
        mock_response_get = Mock()
        mock_response_get.status_code = 200
        mock_response_get.json.return_value = [{"data": {"status": "RUNNING", "test_field": "val"}}]
        
        with patch("requests.get", return_value=mock_response_get) as mock_get:
            snap = doc_ref.get()
            assert snap.exists is True
            assert snap.to_dict() == {"status": "RUNNING", "test_field": "val"}
            mock_get.assert_called_once()
            
        # Test set()
        mock_response_post = Mock()
        mock_response_post.status_code = 201
        
        with patch("requests.post", return_value=mock_response_post) as mock_post:
            doc_ref.set({"status": "COMPLETED"})
            mock_post.assert_called_once()
            
        # Test update()
        mock_response_get_update = Mock()
        mock_response_get_update.status_code = 200
        mock_response_get_update.json.return_value = [{"data": {"logs": ["log1"]}}]

        mock_response_patch = Mock()
        mock_response_patch.status_code = 200
        mock_response_patch.text = '[{"key": "scans/test_doc"}]'
        mock_response_patch.json.return_value = [{"key": "scans/test_doc"}]
        
        with patch("requests.get", return_value=mock_response_get_update), \
             patch("requests.patch", return_value=mock_response_patch) as mock_patch_update:
            doc_ref.update({"logs": ArrayUnion(["log2"])})
            mock_patch_update.assert_called_once()
            
    finally:
        del os.environ["SUPABASE_URL"]
        del os.environ["SUPABASE_KEY"]


def test_supabase_db_caching():
    from unittest.mock import patch, Mock
    import os
    from supabase_db import SupabaseDB, ArrayUnion
    
    os.environ["SUPABASE_URL"] = "https://mock.supabase.co"
    os.environ["SUPABASE_KEY"] = "mock_key"
    
    try:
        db = SupabaseDB()
        doc_ref = db.collection("scans").document("cache_test")
        
        # 1. Mock first set() which populates the cache
        mock_response_post = Mock()
        mock_response_post.status_code = 201
        
        with patch("requests.post", return_value=mock_response_post) as mock_post:
            doc_ref.set({"status": "INIT", "progress": 0})
            mock_post.assert_called_once()
            
        # Verify cache is populated
        assert doc_ref._cached_data == {"status": "INIT", "progress": 0}
        assert doc_ref._cached_encrypted_data is not None
        
        # 2. Update without GET request because cache is active
        mock_response_patch = Mock()
        mock_response_patch.status_code = 200
        mock_response_patch.text = '[{"key": "scans/cache_test"}]'
        mock_response_patch.json.return_value = [{"key": "scans/cache_test"}]
        
        # We patch requests.get to raise AssertionError if called (to verify it is NOT called)
        def get_should_not_be_called(*args, **kwargs):
            raise AssertionError("requests.get was called but cache should have bypassed it!")
            
        with patch("requests.get", side_effect=get_should_not_be_called), \
             patch("requests.patch", return_value=mock_response_patch) as mock_patch:
            doc_ref.update({"progress": 50})
            mock_patch.assert_called_once()
            
        # Verify cache updated with merged dict
        assert doc_ref._cached_data == {"status": "INIT", "progress": 50}
        
    finally:
        del os.environ["SUPABASE_URL"]
        del os.environ["SUPABASE_KEY"]


def test_supabase_jwt_verification():
    import os
    import jwt
    from fastapi import Request
    from unittest.mock import Mock
    from auth import verify_request_uid
    
    # Configure mock Supabase JWT environment
    os.environ["SUPABASE_JWT_SECRET"] = "super_secret_supabase_key"
    
    try:
        # Create token
        token_payload = {"sub": "supabase_user_12345", "role": "authenticated"}
        encoded_token = jwt.encode(token_payload, "super_secret_supabase_key", algorithm="HS256")
        
        mock_request = Mock(spec=Request)
        mock_request.headers = {"Authorization": f"Bearer {encoded_token}"}
        
        uid = verify_request_uid(mock_request, claimed_uid=None)
        assert uid == "supabase_user_12345"
        
    finally:
        del os.environ["SUPABASE_JWT_SECRET"]


def test_custom_auth_login_test123():
    import routes
    from routes import login, register, LoginRequest, RegisterRequest
    
    original_db = routes.db
    routes.db = MockDB()
    try:
        reg_req = RegisterRequest(
            email="test123@example.com",
            password="test123",
            first_name="Test",
            last_name="User"
        )
        register(reg_req)
        
        req = LoginRequest(email="test123@example.com", password="test123")
        res = login(req)
        assert res["username"] == "test123@example.com"
        assert "uid" in res
        assert "token" in res
    finally:
        routes.db = original_db


def test_rate_limiter_concurrency_atomic():
    import routes
    import threading
    import time

    db = MockDB()
    col_name = "rate_limit_concurrency_test"
    doc_id = "test_ip_atomic"
    
    try:
        db.collection(col_name).document(doc_id).delete()
    except Exception:
        pass

    doc_ref = db.collection(col_name).document(doc_id)
    max_requests = 5
    window_seconds = 10

    results = []
    def worker():
        allowed = doc_ref.check_and_update_rate_limit(time.time(), window_seconds, max_requests)
        results.append(allowed)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Out of 8 concurrent requests, exactly 5 must be True and 3 must be False
    assert results.count(True) == 5
    assert results.count(False) == 3


def test_emulator_pool_file_locking():
    from unittest.mock import patch, Mock
    from dynamic_engine import EmulatorPoolManager

    pool = EmulatorPoolManager()
    
    mock_run_res = Mock()
    mock_run_res.stdout = "emulator-5554\tdevice\nemulator-5556\tdevice\n"
    mock_run_res.returncode = 0

    with patch("dynamic_engine._orig_subprocess_run", return_value=mock_run_res):
        # 1. Lease the first device
        dev1 = pool.get_available_device()
        assert dev1 == "emulator-5554"
        assert dev1 in pool.busy_devices
        
        # 2. Try to lease again - should get the second device
        dev2 = pool.get_available_device()
        assert dev2 == "emulator-5556"
        assert dev2 in pool.busy_devices

        # 3. Try to lease a third time - should return None
        dev3 = pool.get_available_device()
        assert dev3 is None

        # 4. Now simulate another EmulatorPoolManager instance in another process trying to lease
        pool_other = EmulatorPoolManager()
        dev_other = pool_other.get_available_device()
        assert dev_other is None

        # 5. Release dev1
        pool.release_device(dev1)
        assert dev1 not in pool.busy_devices

        # 6. Now the other pool instance should be able to lease dev1
        dev_other_leased = pool_other.get_available_device()
        assert dev_other_leased == "emulator-5554"

        # Cleanup
        pool.release_device(dev2)
        pool_other.release_device(dev_other_leased)


def test_gcs_url_safety_check():
    import os
    from main import is_safe_ingest_url
    
    # When KAVACH_ALLOWED_GCS_BUCKETS is set
    os.environ["KAVACH_ALLOWED_GCS_BUCKETS"] = "kavach-scans,kavach-public"
    try:
        assert is_safe_ingest_url("gs://kavach-scans/target.apk") is True
        assert is_safe_ingest_url("gs://kavach-public/target.apk") is True
        assert is_safe_ingest_url("gs://unsafe-bucket/target.apk") is False
    finally:
        del os.environ["KAVACH_ALLOWED_GCS_BUCKETS"]

    # In production without whitelisted env, gs:// should return False
    os.environ["KAVACH_ENV"] = "production"
    try:
        assert is_safe_ingest_url("gs://any-bucket/target.apk") is False
    finally:
        del os.environ["KAVACH_ENV"]


def test_zipbomb_file_count_and_depth():
    import os
    import tempfile
    import zipfile
    import pytest
    from main import _postprocess_downloaded_apk_file
    
    # 1. Test too many files
    fd, temp_zip = tempfile.mkstemp(suffix=".apk")
    os.close(fd)
    try:
        with zipfile.ZipFile(temp_zip, 'w') as z:
            for i in range(10005): # Over limit 10000
                z.writestr(f"file_{i}.txt", "data")
        
        with pytest.raises(Exception, match="contains too many files"):
            _postprocess_downloaded_apk_file(temp_zip)
    finally:
        if os.path.exists(temp_zip):
            os.remove(temp_zip)
            
    # 2. Test too deep directory depth
    fd, temp_zip = tempfile.mkstemp(suffix=".apk")
    os.close(fd)
    try:
        with zipfile.ZipFile(temp_zip, 'w') as z:
            # Depth of 16 (Limit is 15)
            nested_path = "/".join([f"dir{i}" for i in range(16)]) + "/file.txt"
            z.writestr(nested_path, "data")
        
        with pytest.raises(Exception, match="directory nesting depth exceeds maximum"):
            _postprocess_downloaded_apk_file(temp_zip)
    finally:
        if os.path.exists(temp_zip):
            os.remove(temp_zip)


def test_redis_mandatory_in_production():
    import os
    from routes import HybridRateLimiter
    
    os.environ["KAVACH_ENV"] = "production"
    os.environ["REDIS_URL"] = "redis://invalid-nonexistent-redis-host:6379"
    try:
        limiter = HybridRateLimiter("test_prod_limit", 5, 60)
        # Should fail closed and return False because Redis is unreachable in production
        assert limiter.check("127.0.0.1") is False
    finally:
        del os.environ["KAVACH_ENV"]
        del os.environ["REDIS_URL"]











