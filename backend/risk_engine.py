"""
Explainable risk decomposition for Kavach AI using OWASP Risk Rating Methodology.
"""

from typing import Any, Dict, List


def build_risk_decomposition(
    static_score: int,
    dynamic_score: int,
    ai_score: int,
    fraud_score: int,
    contributors: List[Dict[str, Any]] | None = None,
    absolute_score: int = 0,
    profile: str = "default",
) -> Dict[str, Any]:
    """Produce weighted breakdown and top contributors for UI."""
    # Use the AI score directly without artificial dilution when it matches the static score
    independent_ai_score = ai_score

    # Build weights based on profile
    if profile == "frontline":
        # Frontline mode: heavy banking fraud and dynamic behavior, lower static focus
        weights = {
            "static": 0.20,
            "dynamic": 0.40 if dynamic_score > 0 else 0.00,
            "ai": 0.10 if independent_ai_score > 0 else 0.00,
            "banking_fraud": 0.30 if fraud_score > 0 else 0.00
        }
        if weights["dynamic"] == 0 and weights["banking_fraud"] == 0:
            weights["static"] = 0.90
            weights["ai"] = 0.10 if independent_ai_score > 0 else 0.00
    elif profile == "strict_compliance":
        # Strict compliance mode: static patterns and AI analysis are prioritized
        weights = {
            "static": 0.60,
            "dynamic": 0.15 if dynamic_score > 0 else 0.00,
            "ai": 0.15 if independent_ai_score > 0 else 0.00,
            "banking_fraud": 0.10 if fraud_score > 0 else 0.00
        }
    else:
        # Default mode
        if dynamic_score == 0 and fraud_score == 0:
            if independent_ai_score > 0:
                weights = {"static": 0.80, "dynamic": 0.00, "ai": 0.20, "banking_fraud": 0.00}
            else:
                weights = {"static": 1.00, "dynamic": 0.00, "ai": 0.00, "banking_fraud": 0.00}
        elif dynamic_score == 0:
            weights = {
                "static": 0.65,
                "dynamic": 0.00,
                "ai": 0.10 if independent_ai_score > 0 else 0.00,
                "banking_fraud": 0.25,
            }
        else:
            weights = {
                "static": 0.50,
                "dynamic": 0.30,
                "ai": 0.10 if independent_ai_score > 0 else 0.00,
                "banking_fraud": 0.20,
            }

    # Normalise weights so they always sum to 1.0 (prevents systematic bias)
    total_weight = sum(weights.values())
    if total_weight > 0:
        weights = {k: round(v / total_weight, 4) for k, v in weights.items()}

    components = {
        "static": min(100, max(0, static_score)),
        "dynamic": min(100, max(0, dynamic_score)),
        "ai": min(100, max(0, independent_ai_score)),
        "banking_fraud": min(100, max(0, fraud_score)),
    }

    weighted = {k: round(components[k] * weights[k], 1) for k in components}
    composite_base = min(100, round(sum(weighted.values())))
    # Conservative risk rating: ensure severe risks are never diluted
    composite = max(composite_base, static_score, dynamic_score, fraud_score)
    composite = min(100, max(0, composite))


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
        "absolute_score": absolute_score,
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
    return f"Threat score {composite}/100 driven by {', '.join(parts)} ({confidence} confidence)."


def derive_dynamic_score(
    runtime_findings: List[Dict[str, Any]] | None,
    event_count: int,
    sandbox_status: str,
) -> int:
    """
    Calculate dynamic score using transparent Likelihood x Impact matrix model.
    """
    if sandbox_status not in ("COMPLETED",) and not runtime_findings:
        return 0
        
    # 1. Dynamic Likelihood (starts at 1.0)
    L_dyn = 1.0
    if event_count > 0:
        L_dyn += min(4.0, event_count * 0.1)
    if runtime_findings:
        # Playbook steps or live triggers succeeded
        L_dyn += min(5.0, len(runtime_findings) * 1.5)
    L_dyn = min(10.0, L_dyn)
    
    # 2. Dynamic Technical Impact (starts at 1.0)
    I_dyn = 1.0
    exfil_leaks = 0
    sensitive_calls = 0
    
    for f in (runtime_findings or []):
        title = f.get("title", "").lower()
        desc = f.get("description", "").lower()
        sev = (f.get("severity") or "MEDIUM").upper()
        
        # Identify exfiltration, commands, and sensitive behaviors
        if any(x in title or x in desc for x in ("exfiltrat", "leak", "send", "intercept")):
            exfil_leaks += 1.0
        elif any(x in title or x in desc for x in ("crypto", "sqlite", "file", "storage")):
            sensitive_calls += 0.5
            
        weight = {"CRITICAL": 3.0, "HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.5}.get(sev, 1.0)
        I_dyn += weight
        
    I_dyn += (exfil_leaks * 2.5) + (sensitive_calls * 1.5)
    I_dyn = min(10.0, I_dyn)
    
    dynamic_score = int(((L_dyn + I_dyn) / 2.0) * 10)
    return min(100, max(0, dynamic_score))


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
        out.append({
            "label": badge.get("title", "Fraud signal"),
            "category": "banking_fraud",
            "weight": w
        })
        
    for rf in (runtime_findings or [])[:2]:
        out.append({
            "label": rf.get("title", "Runtime finding"),
            "category": "dynamic",
            "weight": 15,
        })
        
    return out
