"""
CVE-Triage-Env: FastAPI application.

Exposes the OpenEnv-compliant REST API for the CVE triage environment,
plus AI-powered analysis (Gemini) and live CVE lookup (NVD API).
Runs on port 7860 for Hugging Face Spaces compatibility.
"""

from __future__ import annotations

import os
import time
from contextlib import asynccontextmanager
from typing import Any

import httpx
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from environment.models import CVEAction, CVEObservation, CVEReward, TaskConfig
from environment.env import CVETriageEnv
from environment.tasks import TASKS

load_dotenv()

# ---------------------------------------------------------------------------
# Gemini AI client (lazy — only initialized if key is present)
# ---------------------------------------------------------------------------
_gemini_model = None

def _get_gemini():
    global _gemini_model
    if _gemini_model is None:
        import google.generativeai as genai
        api_key = os.getenv("GEMINI_API_KEY", "")
        if not api_key:
            raise HTTPException(status_code=500, detail="GEMINI_API_KEY not set in .env")
        genai.configure(api_key=api_key)
        _gemini_model = genai.GenerativeModel("gemini-2.5-flash")
    return _gemini_model


# ---------------------------------------------------------------------------
# Request / response models (API-layer only)
# ---------------------------------------------------------------------------

class ResetRequest(BaseModel):
    """Body for POST /reset."""
    task_id: str = "easy"


class StepResponse(BaseModel):
    """Response for POST /step."""
    observation: dict[str, Any]
    reward: dict[str, Any]
    done: bool
    info: dict[str, Any]


class HealthResponse(BaseModel):
    """Response for GET /health."""
    status: str
    version: str


class AnalyzeRequest(BaseModel):
    """Body for POST /analyze — AI-powered CVE analysis."""
    cve_id: str = Field(..., description="CVE identifier, e.g. CVE-2021-44228")
    description: str = Field(default="", description="Optional CVE description for richer analysis")


class AnalyzeResponse(BaseModel):
    """Response for POST /analyze."""
    cve_id: str
    cause: str
    remediation: str
    severity_assessment: str
    affected_components: str
    recommendation: str


class FetchCVEResponse(BaseModel):
    """Response for GET /fetch_cve/{cve_id}."""
    cve_id: str
    description: str
    cvss_score: float | None
    severity: str
    published: str
    references: list[str]
    weaknesses: list[str]
    affected_products: list[str]
    raw_source: str


# ---------------------------------------------------------------------------
# Lifespan (modern FastAPI pattern — no deprecated @app.on_event)
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise the environment on startup."""
    initial_task = os.getenv("TASK_ID", "easy")
    app.state.env = CVETriageEnv(initial_task)
    yield


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="CVE-Triage-Env",
    description=(
        "A real-world OpenEnv environment where AI agents investigate "
        "CVE IDs to extract GAV metadata and identify vulnerable methods, "
        "simulating the security triage workflow of a DevSecOps engineer. "
        "Now enhanced with Gemini AI analysis and live NVD lookups."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# OpenEnv Routes (unchanged)
# ---------------------------------------------------------------------------

@app.post("/reset", response_model=None)
async def reset_env(body: ResetRequest | None = None) -> dict[str, Any]:
    """Reset the environment, optionally switching tasks."""
    task_id = body.task_id if body else "easy"
    env: CVETriageEnv = app.state.env
    if env.task.task_id != task_id:
        try:
            app.state.env = CVETriageEnv(task_id)
            env = app.state.env
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    obs = env.reset()
    return obs.model_dump()


@app.post("/step", response_model=StepResponse)
async def step_env(action: CVEAction) -> StepResponse:
    """Execute one agent action."""
    env: CVETriageEnv = app.state.env
    try:
        obs, reward, done, info = env.step(action)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return StepResponse(
        observation=obs.model_dump(),
        reward=reward.model_dump(),
        done=done,
        info=info,
    )


@app.get("/state", response_model=None)
async def get_state() -> dict[str, Any]:
    """Return the current environment state."""
    env: CVETriageEnv = app.state.env
    return env.state()


@app.get("/tasks", response_model=None)
async def list_tasks() -> list[dict[str, Any]]:
    """Return all available task definitions."""
    return [t.model_dump() for t in TASKS]


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(status="ok", version="2.0.0")


# ---------------------------------------------------------------------------
# NEW: Live CVE Fetch (NVD API — free, no key required)
# ---------------------------------------------------------------------------

@app.get("/fetch_cve/{cve_id}", response_model=FetchCVEResponse)
async def fetch_cve(cve_id: str) -> FetchCVEResponse:
    """Fetch real-time CVE data from the NIST National Vulnerability Database."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise HTTPException(
                status_code=502, detail=f"NVD API returned {exc.response.status_code}"
            ) from exc
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=502, detail=f"Could not reach NVD API: {exc}"
            ) from exc

    data = resp.json()
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found in NVD")

    cve_data = vulns[0].get("cve", {})

    # Description
    desc_list = cve_data.get("descriptions", [])
    description = next(
        (d["value"] for d in desc_list if d.get("lang") == "en"),
        "No description available"
    )

    # CVSS score
    metrics = cve_data.get("metrics", {})
    cvss_score = None
    severity = "UNKNOWN"

    for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(version_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
            break

    # Published date
    published = cve_data.get("published", "Unknown")

    # References
    refs = [r.get("url", "") for r in cve_data.get("references", [])[:8]]

    # Weaknesses
    weaknesses = []
    for w in cve_data.get("weaknesses", []):
        for wd in w.get("description", []):
            if wd.get("lang") == "en":
                weaknesses.append(wd["value"])

    # Affected products (CPE-based)
    affected = []
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if criteria:
                    parts = criteria.split(":")
                    if len(parts) >= 6:
                        affected.append(f"{parts[3]}:{parts[4]}:{parts[5]}")

    return FetchCVEResponse(
        cve_id=cve_id,
        description=description,
        cvss_score=cvss_score,
        severity=severity,
        published=published[:10] if len(published) > 10 else published,
        references=refs,
        weaknesses=weaknesses,
        affected_products=affected[:10],
        raw_source="NIST NVD (services.nvd.nist.gov)",
    )


# ---------------------------------------------------------------------------
# NEW: AI-Powered Analysis (Google Gemini)
# ---------------------------------------------------------------------------

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_cve(body: AnalyzeRequest) -> AnalyzeResponse:
    """Use Gemini AI to analyze a CVE and provide cause, remediation, and severity."""
    model = _get_gemini()

    prompt = f"""You are a senior cybersecurity analyst. Analyze the following CVE and provide a structured security report.

CVE ID: {body.cve_id}
{f'Description: {body.description}' if body.description else ''}

Provide your analysis in EXACTLY this format (use these exact headers):

CAUSE:
[Explain the root cause of this vulnerability in 2-3 sentences]

REMEDIATION:
[Provide specific remediation steps in 2-3 actionable bullet points]

SEVERITY ASSESSMENT:
[One sentence assessing the real-world severity and exploitability]

AFFECTED COMPONENTS:
[List the affected libraries, frameworks, or components with version ranges]

RECOMMENDATION:
[One clear recommendation for the development team]
"""

    # Retry with exponential backoff for rate-limit errors
    text = None
    last_error = None
    for attempt in range(3):
        try:
            response = model.generate_content(prompt)
            text = response.text
            break
        except Exception as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(2 ** attempt)  # 1s, 2s backoff
            continue
    if text is None:
        raise HTTPException(
            status_code=502, detail=f"Gemini API error after 3 retries: {last_error}"
        )

    # Parse the structured response
    sections = {
        "cause": "",
        "remediation": "",
        "severity_assessment": "",
        "affected_components": "",
        "recommendation": "",
    }

    current_section = None
    for line in text.split("\n"):
        line_upper = line.strip().upper()
        if line_upper.startswith("CAUSE:"):
            current_section = "cause"
            remainder = line.strip()[len("CAUSE:"):].strip()
            if remainder:
                sections["cause"] = remainder
        elif line_upper.startswith("REMEDIATION:"):
            current_section = "remediation"
            remainder = line.strip()[len("REMEDIATION:"):].strip()
            if remainder:
                sections["remediation"] = remainder
        elif line_upper.startswith("SEVERITY ASSESSMENT:"):
            current_section = "severity_assessment"
            remainder = line.strip()[len("SEVERITY ASSESSMENT:"):].strip()
            if remainder:
                sections["severity_assessment"] = remainder
        elif line_upper.startswith("AFFECTED COMPONENTS:"):
            current_section = "affected_components"
            remainder = line.strip()[len("AFFECTED COMPONENTS:"):].strip()
            if remainder:
                sections["affected_components"] = remainder
        elif line_upper.startswith("RECOMMENDATION:"):
            current_section = "recommendation"
            remainder = line.strip()[len("RECOMMENDATION:"):].strip()
            if remainder:
                sections["recommendation"] = remainder
        elif current_section and line.strip():
            sections[current_section] += ("\n" if sections[current_section] else "") + line.strip()

    return AnalyzeResponse(
        cve_id=body.cve_id,
        cause=sections["cause"] or "Analysis unavailable",
        remediation=sections["remediation"] or "Analysis unavailable",
        severity_assessment=sections["severity_assessment"] or "Analysis unavailable",
        affected_components=sections["affected_components"] or "Analysis unavailable",
        recommendation=sections["recommendation"] or "Analysis unavailable",
    )


# ---------------------------------------------------------------------------
# NEW: Serve Frontend (Hugging Face Spaces)
# ---------------------------------------------------------------------------

frontend_dist = os.path.join(os.path.dirname(__file__), "frontend", "dist")

@app.get("/")
async def serve_frontend_index():
    """Serve the React app entry point."""
    if os.path.exists(os.path.join(frontend_dist, "index.html")):
        return FileResponse(os.path.join(frontend_dist, "index.html"))
    return {"message": "CVE-Triage-Env Backend is running. Frontend not built."}

if os.path.exists(frontend_dist):
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=7860,
        reload=False,
    )
