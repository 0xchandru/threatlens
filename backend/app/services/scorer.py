from dataclasses import dataclass


@dataclass
class ScoreResult:
    composite_score: float
    risk_level:      str
    score_breakdown: dict
    confidence:      str


RISK_LEVELS = [
    (20,  "clean"),
    (40,  "low"),
    (60,  "suspicious"),
    (80,  "malicious"),
    (101, "critical"),
]

WEIGHTS = {
    "virustotal":   30,
    "abuseipdb":    23,
    "alienvault":   20,
    "urlhaus":      11,
    "threatfox":    10,
    "malwarebazaar": 6,
}


def calculate_composite_score(results: dict) -> ScoreResult:
    breakdown = {}
    total_weight_available = 0

    score_vt = 0.0
    if vt := results.get("virustotal"):
        if vt.get("status") == "found":
            total = vt.get("total", 0)
            if total > 0:
                malicious  = vt.get("malicious", 0)
                suspicious = vt.get("suspicious", 0)
                ratio = (malicious + suspicious * 0.4) / total
                score_vt = min(ratio * WEIGHTS["virustotal"], WEIGHTS["virustotal"])
            total_weight_available += WEIGHTS["virustotal"]
    breakdown["virustotal"] = round(score_vt, 2)

    score_ai = 0.0
    if ai := results.get("abuseipdb"):
        if ai.get("status") == "found":
            confidence = ai.get("confidence_score", 0)
            score_ai = (confidence / 100) * WEIGHTS["abuseipdb"]
            total_weight_available += WEIGHTS["abuseipdb"]
    breakdown["abuseipdb"] = round(score_ai, 2)

    score_av = 0.0
    if av := results.get("alienvault"):
        if av.get("status") == "found":
            pulse_count = av.get("pulse_count", 0)
            normalized = min(pulse_count / 15, 1.0)
            score_av = normalized * WEIGHTS["alienvault"]
            total_weight_available += WEIGHTS["alienvault"]
    breakdown["alienvault"] = round(score_av, 2)

    score_uh = 0.0
    if uh := results.get("urlhaus"):
        if uh.get("status") == "found":
            if uh.get("url_status") == "online":
                score_uh = WEIGHTS["urlhaus"]
            else:
                score_uh = WEIGHTS["urlhaus"] * 0.4
            total_weight_available += WEIGHTS["urlhaus"]
    breakdown["urlhaus"] = round(score_uh, 2)

    score_tf = 0.0
    if tf := results.get("threatfox"):
        if tf.get("status") == "found":
            confidence = tf.get("confidence_level", 0)
            score_tf = (confidence / 100) * WEIGHTS["threatfox"]
            total_weight_available += WEIGHTS["threatfox"]
    breakdown["threatfox"] = round(score_tf, 2)

    score_mb = 0.0
    if mb := results.get("malwarebazaar"):
        if mb.get("status") == "found":
            detections    = mb.get("detections", 0)
            total_vendors = mb.get("total_vendors", 1) or 1
            ratio = min(detections / total_vendors, 1.0)
            score_mb = ratio * WEIGHTS["malwarebazaar"]
            total_weight_available += WEIGHTS["malwarebazaar"]
    breakdown["malwarebazaar"] = round(score_mb, 2)

    composite = sum(breakdown.values())

    if total_weight_available == 0:
        return ScoreResult(
            composite_score=0.0,
            risk_level="unknown",
            score_breakdown=breakdown,
            confidence="none",
        )

    if total_weight_available >= 80:
        confidence = "high"
    elif total_weight_available >= 40:
        confidence = "medium"
    else:
        confidence = "low"

    risk = next(level for threshold, level in RISK_LEVELS if composite < threshold)

    return ScoreResult(
        composite_score=round(composite, 2),
        risk_level=risk,
        score_breakdown=breakdown,
        confidence=confidence,
    )
