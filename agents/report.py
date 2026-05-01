import json
import os
import uuid
from datetime import datetime, timezone
import anthropic
from dotenv import load_dotenv

load_dotenv()

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

SYSTEM_PROMPT = """You are a senior security analyst writing an incident report for a SOC team.
You will receive structured data from triage and specialist agents. Write a professional incident report.

Return a JSON object with exactly these fields:

{
  "incident_id": use the one provided,
  "timestamp": use the one provided,
  "severity": from triage,
  "executive_summary": "3-4 sentences suitable for a non-technical manager",
  "threat_overview": "2-3 sentences describing the technical nature of the threat",
  "findings": list of key findings as plain strings (one per agent result),
  "compliance_impact": list of compliance frameworks affected (pull from agent results),
  "recommended_actions": prioritized list of 5 actions, each prefixed with P1/P2/P3,
  "conclusion": "1-2 sentences on overall risk and next step"
}

Return only valid JSON. No markdown, no explanation."""


def run_report(event: str, triage: dict, agent_results: dict) -> dict:
    incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.now(timezone.utc).isoformat()

    prompt = f"""Generate an incident report for the following:

Incident ID: {incident_id}
Timestamp: {timestamp}
Original event: {event}
Triage result: {json.dumps(triage)}
Agent findings: {json.dumps(agent_results)}"""

    message = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = message.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    return json.loads(raw)
