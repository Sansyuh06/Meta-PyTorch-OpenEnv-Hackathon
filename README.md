# 🛡️ CVE-Triage-Env

> **Created originally for the Meta-PyTorch-OpenEnv-Hackathon**
>
> A real-world **OpenEnv-compliant** AI agent training environment where agents investigate CVE IDs to extract GAV (Group–Artifact–Version) metadata and identify vulnerable methods — simulating the security triage workflow of a DevSecOps engineer.

[![OpenEnv](https://img.shields.io/badge/OpenEnv-Compliant-00d4aa?style=for-the-badge&logo=openai&logoColor=white)](https://github.com/openenv)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

---

## 🔍 Overview

Security teams spend **hours per CVE** manually researching vulnerability details, tracking down affected libraries, identifying vulnerable methods, and verifying whether their codebase actually calls those methods. **CVE-Triage-Env** turns this real-world workflow into a structured agent environment with measurable, graded performance across three difficulty levels.

Agents interact through the standard `step()` / `reset()` / `state()` interface, taking **sequential investigation actions** — querying NVD, fetching advisories, analyzing patches, scanning code — before submitting their findings for **deterministic grading** with partial credit.

### Why This Matters

| Metric | Impact |
|--------|--------|
| **Manual CVE triage time** | 2–4 hours per vulnerability |
| **Annual CVEs published** | 25,000+ (2024) |
| **Security team burnout** | #1 cited reason for analyst turnover |

This environment lets AI agents learn to automate the most time-consuming part of vulnerability management — so human engineers can focus on remediation, not research.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                    AI Agent (LLM)                    │
│  Observes → Reasons → Acts → Observes → ...         │
└──────────────────────┬──────────────────────────────┘
                       │ CVEAction (JSON)
                       ▼
┌─────────────────────────────────────────────────────┐
│              CVETriageEnv (OpenEnv)                   │
│                                                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │
│  │  reset()  │  │  step()  │  │     state()      │   │
│  └────┬─────┘  └────┬─────┘  └──────────────────┘   │
│       │              │                                │
│       ▼              ▼                                │
│  ┌──────────────────────────────────────────────┐    │
│  │            ActionHandler                      │    │
│  │  search_nvd │ fetch_advisory │ lookup_gav     │    │
│  │  search_method │ scan_code │ submit           │    │
│  └──────────────────┬───────────────────────────┘    │
│                     │                                 │
│  ┌──────────────────▼───────────────────────────┐    │
│  │          Pre-cached Fixtures (JSON)            │    │
│  │  CVE-2021-44228 │ CVE-2022-22965              │    │
│  │  CVE-2022-42889 │ CVE-2021-42550              │    │
│  └──────────────────────────────────────────────┘    │
│                     │                                 │
│  ┌──────────────────▼───────────────────────────┐    │
│  │          Deterministic Grader                  │    │
│  │  Partial credit │ Penalties │ [0.0, 1.0]      │    │
│  └──────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

---

## 🎯 Action Space

| Action | Parameters | Returns | Purpose |
|--------|-----------|---------|---------|
| `search_nvd` | — | NVD vulnerability record (description, CVSS, CWEs) | Initial CVE reconnaissance |
| `fetch_advisory` | — | GitHub Security Advisory (severity, patched versions) | Cross-reference vulnerability data |
| `lookup_gav` | — | GAV coordinates (group, artifact, versions, safe ver.) | Identify affected dependency |
| `search_method` | — | Vulnerable method details + patch diff | Pinpoint the vulnerable code |
| `scan_code` | — | Synthetic code snippet + invocation boolean | Check if vulnerability is reachable |
| `submit` | `dict` of answers | Triggers grading, ends episode | Submit investigation findings |

## 👁️ Observation Space

| Field | Type | Description |
|-------|------|-------------|
| `cve_id` | `str` | The CVE being investigated |
| `step_number` | `int` | Current step in the episode |
| `action_history` | `list[str]` | Actions taken so far |
| `current_output` | `dict` | Result of the last action |
| `available_actions` | `list[str]` | All valid action types |
| `episode_done` | `bool` | Whether the episode has ended |

---

## 📋 Tasks

| ID | Difficulty | CVE | Objective | Max Steps | Required Investigation Path |
|----|-----------|-----|-----------|-----------|---------------------------|
| `easy` | 🟢 Easy | CVE-2022-42889 | Extract GAV coordinates + safe version | 5 | `search_nvd` → `lookup_gav` → `submit` |
| `medium` | 🟡 Medium | CVE-2021-44228 | Identify vulnerable method + GAV | 8 | `search_nvd` → `fetch_advisory` → `search_method` → `submit` |
| `hard` | 🔴 Hard | CVE-2022-22965 | Full investigation + invocation check | 12 | All 5 actions → `submit` |

### Featured CVEs

| CVE | Common Name | Component | Impact |
|-----|------------|-----------|--------|
| CVE-2022-42889 | **Text4Shell** | Apache Commons Text `StringSubstitutor` | RCE via string interpolation |
| CVE-2021-44228 | **Log4Shell** | Apache Log4j `JndiLookup` | RCE via JNDI injection (CVSS 10.0) |
| CVE-2022-22965 | **Spring4Shell** | Spring Framework `DataBinder` | RCE via data binding on JDK 9+ |
| CVE-2021-42550 | **Logback RCE** | Logback `SaxEventRecorder` | RCE via malicious XML config |

---

## 🏆 Reward Structure

### Easy Task — GAV Extraction (max 1.0)

| Component | Max Value | Trigger |
|-----------|-----------|---------|
| `gav_correct` | **+0.40** | Correct group + artifact |
| `version_correct` | **+0.30** | Correct safe version |
| `efficiency_bonus` | **+0.20** | Completed in ≤4 steps |
| `early_submit_penalty` | **-0.10** | Submitted before any research |

### Medium Task — Method Discovery (max 1.0)

| Component | Max Value | Trigger |
|-----------|-----------|---------|
| `gav_correct` | **+0.30** | Correct group + artifact |
| `method_correct` | **+0.30** | Correct vulnerable method (case-insensitive) |
| `version_correct` | **+0.20** | Correct safe version |
| `coverage_bonus` | **+0.20** | Used all required action types |
| `redundancy_penalty` | **-0.10/ea** | Per redundant repeated action (capped -0.30) |

### Hard Task — Invocation Check (max 1.0)

| Component | Max Value | Trigger |
|-----------|-----------|---------|
| `gav_correct` | **+0.25** | Correct group + artifact |
| `method_correct` | **+0.20** | Correct vulnerable method |
| `invocation_correct` | **+0.30** | Correct invocation boolean |
| `version_correct` | **+0.15** | Correct safe version |
| `full_coverage_bonus` | **+0.10** | Used all 5 investigation actions |
| `overstep_penalty` | **-0.05/ea** | Per step beyond 10 (capped -0.30) |

---

## 📊 Baseline Scores

| Task | Model | Score |
|------|-------|-------|
| `easy` | Qwen/Qwen2.5-72B-Instruct | TBD |
| `medium` | Qwen/Qwen2.5-72B-Instruct | TBD |
| `hard` | Qwen/Qwen2.5-72B-Instruct | TBD |

---

## 🚀 Setup

### Local Development

```bash
pip install -r requirements.txt
python run.py
```

The server starts on `http://localhost:7860` with interactive Swagger docs at `/docs`.

### Docker

```bash
docker build -t cve-triage-env .
docker run -p 7860:7860 cve-triage-env
```

### Run Inference

```bash
export HF_TOKEN=your_token
export API_BASE_URL=https://router.huggingface.co/v1
export MODEL_NAME=Qwen/Qwen2.5-72B-Instruct
python inference.py
```

### Run Tests

```bash
# Environment unit tests (no server needed)
python test_env.py

# API integration tests (no server needed — uses TestClient)
python test_api.py
```

---

## 📡 API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/reset` | Reset environment (optionally switch task via `{"task_id": "hard"}`) |
| `POST` | `/step` | Execute one agent action (`{"action_type": "...", "parameters": {...}}`) |
| `GET` | `/state` | Return current environment state |
| `GET` | `/tasks` | List all available task definitions |
| `GET` | `/health` | Health check (`{"status": "ok", "version": "1.0.0"}`) |

---

## ⚙️ Environment Variables

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `TASK_ID` | `easy` | No | Initial task to load on startup |
| `HF_TOKEN` | — | Yes* | Hugging Face API token (*inference only) |
| `API_BASE_URL` | `https://router.huggingface.co/v1` | No | LLM API base URL |
| `MODEL_NAME` | `Qwen/Qwen2.5-72B-Instruct` | No | Model to use for inference |

---

## ✅ OpenEnv Compliance

This environment implements the full OpenEnv specification:

| Interface | Implementation | Status |
|-----------|---------------|--------|
| `reset()` | Returns initial `CVEObservation` with task context | ✅ |
| `step(action)` | Returns `(observation, reward, done, info)` tuple | ✅ |
| `state()` | Returns serializable environment state dict | ✅ |
| Deterministic grading | Fixed fixtures, no live API calls | ✅ |
| Partial credit | Multi-component scoring per task | ✅ |
| Episode boundaries | Submit action or max-step timeout | ✅ |

---

## 📁 Project Structure

```
cve-triage-env/
├── environment/
│   ├── __init__.py          # Package exports (safe import order)
│   ├── models.py            # Pydantic v2 data models
│   ├── actions.py           # Action handler (fixture-based dispatch)
│   ├── graders.py           # Deterministic scoring rubrics
│   ├── tasks.py             # Task definitions + ground truth
│   ├── env.py               # OpenEnv-compliant environment class
│   └── fixtures/            # Pre-cached CVE data (4 real CVEs)
│       ├── CVE-2021-44228.json  (Log4Shell)
│       ├── CVE-2022-22965.json  (Spring4Shell)
│       ├── CVE-2022-42889.json  (Text4Shell)
│       └── CVE-2021-42550.json  (Logback RCE)
├── app.py                   # FastAPI server (port 7860, lifespan pattern)
├── inference.py             # Baseline LLM agent with conversation memory
├── run.py                   # Human-friendly launcher
├── test_env.py              # 12 environment unit tests
├── test_api.py              # 10 API integration tests (TestClient)
├── openenv.yaml             # OpenEnv specification
├── Dockerfile               # Production container (Python 3.11-slim)
├── requirements.txt         # Pinned dependencies
└── README.md                # This file
```

---

## 🔬 Design Decisions

1. **Fixture-based determinism**: All CVE data is pre-cached as JSON fixtures. No live API calls during evaluation ensures reproducible grading across all runs.

2. **Dispatch table routing**: Actions are routed via a dict map (not if/elif chains) for clean extensibility.

3. **Partial credit scoring**: Every task awards partial credit across multiple components, giving agents meaningful gradient signal during training.

4. **String-to-bool coercion**: The hard task grader accepts both `"false"` and `false` for the `invoked` field, handling real LLM output variance.

5. **Conversation memory**: The inference agent maintains conversation history across steps, enabling it to reference prior observations when making decisions.

6. **Robust JSON extraction**: The inference script handles markdown-wrapped, prefix-contaminated, and nested JSON from LLM outputs using regex fallback parsing.

---

## License

MIT
