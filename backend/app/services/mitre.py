from dataclasses import dataclass


@dataclass
class MITRETechnique:
    technique_id: str
    technique:    str
    tactic:       str
    confidence:   str
    source:       str


MAPPING_RULES = [
    {
        "condition": lambda r: (
            r.get("virustotal") and
            r["virustotal"].get("malicious", 0) > 5 and
            "trojan" in str(r["virustotal"].get("tags", [])).lower()
        ),
        "technique_id": "T1204.002",
        "technique":    "Malicious File",
        "tactic":       "execution",
        "confidence":   "high",
        "source":       "virustotal",
    },
    {
        "condition": lambda r: (
            r.get("virustotal") and
            r["virustotal"].get("status") == "found" and
            r["virustotal"].get("malicious", 0) > 0
        ),
        "technique_id": "T1071",
        "technique":    "Application Layer Protocol",
        "tactic":       "command-and-control",
        "confidence":   "medium",
        "source":       "virustotal",
    },
    {
        "condition": lambda r: (
            r.get("abuseipdb") and
            r["abuseipdb"].get("confidence_score", 0) > 70
        ),
        "technique_id": "T1046",
        "technique":    "Network Service Discovery",
        "tactic":       "discovery",
        "confidence":   "medium",
        "source":       "abuseipdb",
    },
    {
        "condition": lambda r: (
            r.get("abuseipdb") and
            r["abuseipdb"].get("is_tor") is True
        ),
        "technique_id": "T1090.003",
        "technique":    "Multi-hop Proxy",
        "tactic":       "command-and-control",
        "confidence":   "high",
        "source":       "abuseipdb",
    },
    {
        "condition": lambda r: (
            r.get("alienvault") and
            any("phishing" in t.lower()
                for t in r["alienvault"].get("tags", []))
        ),
        "technique_id": "T1566",
        "technique":    "Phishing",
        "tactic":       "initial-access",
        "confidence":   "high",
        "source":       "alienvault",
    },
    {
        "condition": lambda r: (
            r.get("alienvault") and
            len(r["alienvault"].get("adversaries", [])) > 0
        ),
        "technique_id": "T1588",
        "technique":    "Obtain Capabilities",
        "tactic":       "resource-development",
        "confidence":   "medium",
        "source":       "alienvault",
    },
    {
        "condition": lambda r: (
            r.get("urlhaus") and
            r["urlhaus"].get("url_status") == "online"
        ),
        "technique_id": "T1105",
        "technique":    "Ingress Tool Transfer",
        "tactic":       "command-and-control",
        "confidence":   "high",
        "source":       "urlhaus",
    },
    {
        "condition": lambda r: (
            r.get("threatfox") and
            r["threatfox"].get("status") == "found" and
            r["threatfox"].get("confidence_level", 0) >= 75
        ),
        "technique_id": "T1595",
        "technique":    "Active Scanning",
        "tactic":       "reconnaissance",
        "confidence":   "high",
        "source":       "threatfox",
    },
    {
        "condition": lambda r: (
            r.get("threatfox") and
            r["threatfox"].get("status") == "found" and
            any("botnet" in str(t).lower() for t in r["threatfox"].get("threat_types", []))
        ),
        "technique_id": "T1583.005",
        "technique":    "Botnet",
        "tactic":       "resource-development",
        "confidence":   "high",
        "source":       "threatfox",
    },
    {
        "condition": lambda r: (
            r.get("malwarebazaar") and
            r["malwarebazaar"].get("status") == "found"
        ),
        "technique_id": "T1027",
        "technique":    "Obfuscated Files or Information",
        "tactic":       "defense-evasion",
        "confidence":   "medium",
        "source":       "malwarebazaar",
    },
]


def map_to_mitre(aggregated_results: dict) -> list[MITRETechnique]:
    matched = {}
    for rule in MAPPING_RULES:
        try:
            if rule["condition"](aggregated_results):
                tid = rule["technique_id"]
                if tid not in matched:
                    matched[tid] = MITRETechnique(
                        technique_id=rule["technique_id"],
                        technique=rule["technique"],
                        tactic=rule["tactic"],
                        confidence=rule["confidence"],
                        source=rule["source"],
                    )
        except (KeyError, TypeError):
            continue
    return list(matched.values())
