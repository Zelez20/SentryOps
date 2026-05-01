import json
import os
import anthropic
from dotenv import load_dotenv

load_dotenv()

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

SYSTEM_PROMPT = """You are a security triage agent. Analyze the security event and return ONLY a JSON object with these exact fields:

{
  "threat_type": one of ["brute_force", "malicious_ip", "cloud_misconfiguration", "unknown"],
  "severity": one of ["low", "medium", "high", "critical"],
  "route_to": array of agents to handle this, choose from ["threat_intel", "cloud_security"],
  "summary": one sentence describing the threat
}

Routing rules:
- brute_force with cloud indicators → ["threat_intel", "cloud_security"]
- malicious IP or domain → ["threat_intel"]
- cloud misconfiguration (S3, IAM, exposed buckets) → ["cloud_security"]
- anything else → ["threat_intel"]

Return only valid JSON. No markdown, no explanation, no code blocks."""


def run_triage(event: str) -> dict:
    message = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=512,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": event}]
    )

    raw = message.content[0].text.strip()

    # Claude sometimes wraps JSON in markdown code blocks despite instructions
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    return json.loads(raw)
