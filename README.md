---
title: CVE Triage Env
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
pinned: false
---

# 🛡️ CVE-Triage-Env

> **Meta-PyTorch-OpenEnv-Hackathon Submission**
>
> A real-world **OpenEnv-compliant** AI agent training environment wrapped in a fully functional **Security Operations Center (SOC) Dashboard**. Agents investigate CVE IDs to extract metadata and pinpoint vulnerable methods, while developers can use the integrated AI Analyzer to summarize zero-day vulnerabilities in real-time.

[![OpenEnv](https://img.shields.io/badge/OpenEnv-Compliant-00d4aa?style=for-the-badge&logo=openai&logoColor=white)](https://github.com/openenv)
[![React](https://img.shields.io/badge/React-18.2+-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![Gemini](https://img.shields.io/badge/Gemini_2.5_Flash-AI-8E75B2?style=for-the-badge)](https://aistudio.google.com/)

---

## 🛠️ How It Works

This project is built in two distinct layers: The **Training Environment** (for AI Models) and the **SOC Dashboard** (for Humans).

### 1. The OpenEnv Training Sandbox (Backend)
Designed as a deterministic testing arena for LLM agents (like Meta's Llama 3 or Qwen). 
- Agents interact via an OpenEnv-compliant API (`/reset`, `/step`).
- Instead of hitting live internet endpoints which may change or go down, the environment serves **static, pre-cached JSON fixtures** (code snippets, patch diffs, GHSA advisories) for famous vulnerabilities like *Log4Shell* and *Spring4Shell*.
- Agents take sequence actions (`scan_code`, `search_method`) to find the vulnerable method and submit their answer for automatic, partial-credit grading.

### 2. The AI SOC Dashboard (Frontend)
A premium dark-mode React application that acts as a visual interface for humans.
- **RL Environment Builder:** Allows human developers to "play" the AI agent role, executing actions and verifying the backend's deterministic JSON responses.
- **AI CVE Analyzer:** We integrated live fetching from the NIST National Vulnerability Database (NVD) coupled with **Google Gemini 2.5 Flash**. You can enter any real-world CVE ID, fetch its live data, and have Gemini instantaneously break down the Root Cause, Remediation steps, and Severity assessment into a beautiful report.

---

## 🚀 How to Run It

This project is Dockerized and completely ready for out-of-the-box local or cloud deployment.

### 🔑 Prerequisites
If you want to use the **AI CVE Analyzer** tab, you need a Gemini AI Key (the RL baseline grader works without it).
Create a `.env` file in the root directory:
```env
GEMINI_API_KEY=your_gemini_api_key_here
```

### Option A: Local Development (FastAPI + Vite)
Run the backend and frontend separately for instant hot-reloading.

**1. Start the API Backend (Terminal 1):**
```bash
pip install -r requirements.txt
python run.py
```
*(Runs on `http://localhost:7860`)*

**2. Start the React Frontend (Terminal 2):**
```bash
cd frontend
npm install
npm run dev
```
*(Runs on `http://localhost:5173`)*

### Option B: Docker (Single Container)
Our multi-stage Dockerfile builds the Vite frontend and mounts it statically into the FastAPI backend so everything runs seamlessly on port `7860`.

```bash
docker build -t cve-triage-env .
docker run -p 7860:7860 -e GEMINI_API_KEY=your_key cve-triage-env
```
Visit `http://localhost:7860` in your browser!

### Option C: Hugging Face Spaces (Instant Deployment)
This repository is pre-configured to run perfectly on Hugging Face Spaces.
1. Create a new Space and select **Docker** -> **Blank** template.
2. In the Space Settings, under **Variables and secrets**, add a new secret named `GEMINI_API_KEY` with your token.
3. Push this repository to the space. Hugging Face will automatically read the `Dockerfile`, build the React UI, and expose the entire application on the web.

---

## 🤖 Running Automated Inference

To test an AI Agent natively against the backend using Hugging Face endpoints:

```bash
export HF_TOKEN=your_hf_token
export API_BASE_URL=https://router.huggingface.co/v1
export MODEL_NAME=Qwen/Qwen2.5-72B-Instruct

python inference.py
```
*The script outputs exact `[START]`, `[STEP]`, and `[END]` stdout formats required for automated hackathon grading.*

---

## 📋 Task Details

| ID | Difficulty | CVE | Objective | Max Steps | Required Investigation Path |
|----|-----------|-----|-----------|-----------|---------------------------|
| `easy` | 🟢 Easy | CVE-2022-42889 | Extract GAV coordinates + safe version | 5 | `search_nvd` → `lookup_gav` → `submit` |
| `medium` | 🟡 Medium | CVE-2021-44228 | Identify vulnerable method + GAV | 8 | `search_nvd` → `fetch_advisory` → `search_method` → `submit` |
| `hard` | 🔴 Hard | CVE-2022-22965 | Full investigation + invocation check | 12 | All 5 actions → `submit` |

### Featured Fixed Fixtures
- **CVE-2021-44228 (Log4Shell):** Apache Log4j `JndiLookup`
- **CVE-2022-22965 (Spring4Shell):** Spring Framework `DataBinder`
- **CVE-2022-42889 (Text4Shell):** Apache Commons Text `StringSubstitutor`
- **CVE-2021-42550 (Logback RCE):** Logback `SaxEventRecorder`

---

## 🏗️ Architecture Stack
- **Backend Framework:** FastAPI (Uvicorn, Pydantic v2)
- **Frontend Framework:** React 18, Vite, vanilla CSS (Glassmorphism design)
- **LLM Integration:** `google-generativeai` (Gemini-2.5-Flash)
- **Standard:** OpenEnv PyTorch Protocol (`reset()`, `step()`, `state()`)

---
