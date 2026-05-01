import os
import asyncio
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import anthropic
from agents.triage import run_triage
from agents.threat_intel import run_threat_intel
from agents.cloud_security import run_cloud_security
from agents.report import run_report

load_dotenv()

app = FastAPI()
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
async def root():
    return FileResponse("static/index.html")


@app.get("/analyze")
async def analyze(event: str):
    message = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=1024,
        messages=[{"role": "user", "content": f"Analyze this security event: {event}"}],
    )
    return {"response": message.content[0].text}


@app.get("/triage")
async def triage(event: str):
    return run_triage(event)


@app.get("/analyze-full")
async def analyze_full(event: str):
    triage_result = run_triage(event)
    agents_to_run = triage_result.get("route_to", [])

    async def call_threat_intel():
        return await asyncio.to_thread(run_threat_intel, event, triage_result)

    async def call_cloud_security():
        return await asyncio.to_thread(run_cloud_security, event, triage_result)

    tasks = []
    if "threat_intel" in agents_to_run:
        tasks.append(("threat_intel", call_threat_intel()))
    if "cloud_security" in agents_to_run:
        tasks.append(("cloud_security", call_cloud_security()))

    results = await asyncio.gather(*[t[1] for t in tasks])
    agent_outputs = {tasks[i][0]: results[i] for i in range(len(tasks))}

    return {"event": event, "triage": triage_result, "agent_results": agent_outputs}


@app.get("/report")
async def report(event: str):
    triage_result = run_triage(event)
    agents_to_run = triage_result.get("route_to", [])

    async def call_threat_intel():
        return await asyncio.to_thread(run_threat_intel, event, triage_result)

    async def call_cloud_security():
        return await asyncio.to_thread(run_cloud_security, event, triage_result)

    tasks = []
    if "threat_intel" in agents_to_run:
        tasks.append(("threat_intel", call_threat_intel()))
    if "cloud_security" in agents_to_run:
        tasks.append(("cloud_security", call_cloud_security()))

    results = await asyncio.gather(*[t[1] for t in tasks])
    agent_outputs = {tasks[i][0]: results[i] for i in range(len(tasks))}

    final_report = await asyncio.to_thread(run_report, event, triage_result, agent_outputs)
    return final_report
