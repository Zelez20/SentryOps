import json
import os
import anthropic
from dotenv import load_dotenv

load_dotenv()

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

SYSTEM_PROMPT = """You are a cloud security analyst specializing in AWS security. Analyze the security event and return a JSON report with exactly these fields:

{
  "misconfiguration_type": one of ["public_storage", "iam_issue", "network_exposure", "encryption_missing", "logging_disabled", "other"],
  "affected_service": the AWS service involved (e.g. "S3", "IAM", "EC2", "RDS"),
  "risk_level": one of ["low", "medium", "high", "critical"],
  "compliance_violations": list of compliance frameworks violated (e.g. ["CIS", "SOC2", "HIPAA"]),
  "remediation_steps": list of 3-5 specific remediation actions,
  "analysis": "2-3 sentence summary of the risk and business impact"
}

Return only valid JSON. No markdown, no explanation."""


def run_cloud_security(event: str, triage: dict) -> dict:
    prompt = f"""Security event: {event}

Triage result: {triage}

Produce the cloud security analysis report."""

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

    return json.loads(raw)
