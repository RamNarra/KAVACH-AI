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
