"""
Explainable risk decomposition for Kavach AI.
"""

from typing import Any, Dict, List


def build_risk_decomposition(
    static_score: int,
    dynamic_score: int,
    ai_score: int,
    fraud_score: int,
    contributors: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    """Produce weighted breakdown and top contributors for UI."""
    weights = {
        "static": 0.35,
        "dynamic": 0.25,
        "ai": 0.25,
        "banking_fraud": 0.15,
    }
    components = {
        "static": min(100, static_score),
        "dynamic": min(100, dynamic_score),
        "ai": min(100, ai_score),
        "banking_fraud": min(100, fraud_score),
    }
    weighted = {k: round(components[k] * weights[k], 1) for k in components}
    composite = min(100, round(sum(weighted.values())))

    top = sorted(contributors or [], key=lambda x: x.get("weight", 0), reverse=True)[:5]

    confidence = "high"
    if components["dynamic"] == 0:
        confidence = "medium"
    if components["dynamic"] == 0 and components["banking_fraud"] == 0:
        confidence = "low"

    return {
        "composite_score": composite,
        "components": components,
        "weights": weights,
        "weighted_contribution": weighted,
        "top_contributors": top,
        "confidence": confidence,
        "summary": _explain(composite, components, confidence),
    }


def _explain(composite: int, components: Dict[str, int], confidence: str) -> str:
    parts = []
    if components["banking_fraud"] >= 40:
        parts.append("elevated banking fraud indicators")
    if components["dynamic"] >= 30:
        parts.append("runtime behavior confirmed")
    elif components["dynamic"] == 0:
        parts.append("no runtime telemetry")
    if components["static"] >= 50:
        parts.append("strong static signals")
    if not parts:
        parts.append("baseline static profile")
    return f"Score {composite}/100 driven by {', '.join(parts)} ({confidence} confidence)."


def derive_dynamic_score(
    runtime_findings: List[Dict[str, Any]] | None,
    event_count: int,
    sandbox_status: str,
) -> int:
    if sandbox_status not in ("COMPLETED",) and not runtime_findings:
        return 0
    sev_weights = {"CRITICAL": 25, "HIGH": 18, "MEDIUM": 12, "LOW": 6, "INFO": 2}
    raw = sum(sev_weights.get((f.get("severity") or "MEDIUM").upper(), 10) for f in (runtime_findings or []))
    raw += min(20, event_count // 2)
    return min(100, raw)


def build_contributors(
    evidence: Dict[str, Any],
    banking_badges: List[Dict[str, Any]],
    runtime_findings: List[Dict[str, Any]] | None,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for perm in (evidence.get("permissions") or [])[:3]:
        out.append({
            "label": perm.get("name") or perm.get("description", "Permission"),
            "category": "static",
            "weight": perm.get("risk_score", 10),
        })
    for badge in banking_badges[:3]:
        w = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 12}.get(badge.get("severity", "MEDIUM"), 10)
        out.append({"label": badge.get("title", "Fraud signal"), "category": "banking_fraud", "weight": w})
    for rf in (runtime_findings or [])[:2]:
        out.append({
            "label": rf.get("title", "Runtime finding"),
            "category": "dynamic",
            "weight": 15,
        })
    return out
