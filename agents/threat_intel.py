import json
import os
import re
import httpx
import anthropic
from dotenv import load_dotenv

load_dotenv()

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")

SYSTEM_PROMPT = """You are a threat intelligence analyst. You will receive a security event and external threat data.
Synthesize this into a structured report with exactly these fields:

{
  "ip_reputation": one of ["malicious", "suspicious", "clean", "unknown"],
  "confidence": integer 0-100,
  "known_threats": list of known malware families, botnets, or campaigns,
  "abuse_reports": integer number of abuse reports,
  "recommendation": one of ["block", "monitor", "investigate"],
  "analysis": "2-3 sentence analyst summary"
}

Return only valid JSON. No markdown, no explanation."""

MOCK_DATA = {
    "virustotal": {"malicious": 47, "suspicious": 12},
    "abuseipdb": {"abuse_confidence": 89, "total_reports": 234, "country": "RU"},
}


def extract_ip(event: str) -> str | None:
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", event)
    return match.group() if match else None


def fetch_virustotal(ip: str) -> dict | None:
    if not VIRUSTOTAL_KEY:
        return None
    try:
        r = httpx.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=10,
        )
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
    except Exception:
        pass
    return None


def fetch_abuseipdb(ip: str) -> dict | None:
    if not ABUSEIPDB_KEY:
        return None
    try:
        r = httpx.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json()["data"]
            return {
                "abuse_confidence": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", "unknown"),
            }
    except Exception:
        pass
    return None


def run_threat_intel(event: str, triage: dict) -> dict:
    ip = extract_ip(event)
    threat_data = {}
    using_mock = False

    if ip:
        vt = fetch_virustotal(ip)
        abuse = fetch_abuseipdb(ip)
        using_mock = vt is None and abuse is None
        threat_data = {
            "ip": ip,
            "virustotal": vt or MOCK_DATA["virustotal"],
            "abuseipdb": abuse or MOCK_DATA["abuseipdb"],
        }
    else:
        threat_data["note"] = "no IP found in event, analyzing context only"

    prompt = f"""Security event: {event}

Triage result: {triage}

External threat data: {threat_data}

Produce the threat intelligence report."""

    message = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=512,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = message.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    result = json.loads(raw)
    result["data_source"] = "mock" if using_mock else "live"
    return result
