"""
CVE-Triage-Env: Baseline inference script.

Runs all three tasks sequentially using an LLM via the OpenAI-compatible
Hugging Face Inference API.  Emits mandatory stdout format for evaluation.

Mandatory output format:
    [START] task=<task_id> env=cve-triage-env model=<MODEL_NAME>
    [STEP] step=<n> action=<action_type> reward=<0.00> done=<true|false> error=<msg|null>
    [END] success=<true|false> steps=<n> rewards=<r1,r2,...,rn>
"""

from __future__ import annotations

import json
import os
import sys
import re
from typing import Any

from openai import OpenAI

from environment.env import CVETriageEnv
from environment.models import CVEAction
from environment.tasks import TASKS

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

HF_TOKEN = os.getenv("HF_TOKEN")
if not HF_TOKEN:
    print("ERROR: HF_TOKEN environment variable is not set.")
    print("Set it with:  export HF_TOKEN=hf_your_token_here")
    sys.exit(1)

API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")

# Optional - if you use from_docker_image():
LOCAL_IMAGE_NAME = os.getenv("LOCAL_IMAGE_NAME")

client = OpenAI(api_key=HF_TOKEN, base_url=API_BASE_URL)

SYSTEM_PROMPT = (
    "You are a security triage agent investigating CVEs. "
    "At each step you receive an observation JSON. "
    "Respond ONLY with a valid JSON object with exactly two keys: "
    "action_type (string) and parameters (dict). "
    "No explanation. No markdown. No code fences. Raw JSON only.\n\n"
    "Valid action_type values: search_nvd, fetch_advisory, lookup_gav, "
    "search_method, scan_code, submit\n\n"
    "When you submit, include all findings in parameters. For example:\n"
    '{"action_type": "submit", "parameters": {"group": "...", '
    '"artifact": "...", "safe_version": "..."}}\n\n'
    "For non-submit actions:\n"
    '{"action_type": "search_nvd", "parameters": {}}'
)


def _extract_json(raw: str) -> dict[str, Any]:
    """Extract and parse JSON from potentially messy LLM output.

    Handles markdown fences, leading text, and common formatting issues.
    """
    text = raw.strip()

    # Strip markdown code fences
    if "```" in text:
        # Find content between fences
        match = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
        if match:
            text = match.group(1).strip()

    # Try direct JSON parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try to find a JSON object in the text
    match = re.search(r"\{[^{}]*\}", text)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    # Try to find nested JSON object
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    raise json.JSONDecodeError("No valid JSON found in response", text, 0)


# ---------------------------------------------------------------------------
# Run a single task
# ---------------------------------------------------------------------------


def run_task(task_id: str) -> None:
    """Run one episode of the given task and print mandatory output."""
    env = CVETriageEnv(task_id)
    obs = env.reset()

    rewards: list[float] = []
    steps: int = 0
    error_msg: str = "null"
    success: bool = False

    # Build conversation history for context across steps
    conversation: list[dict[str, str]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
    ]

    print(f"[START] task={task_id} env=cve-triage-env model={MODEL_NAME}")

    try:
        while not obs.episode_done:
            # Build user message with current observation
            obs_dump = obs.model_dump()
            user_content = (
                f"Current observation:\n{json.dumps(obs_dump, indent=2)}\n\n"
                f"Available actions: {obs.available_actions}\n"
                f"Step {obs.step_number + 1} of {env.task.max_steps}.\n"
                "What is your next action? Respond with JSON only."
            )

            conversation.append({"role": "user", "content": user_content})

            # Keep conversation manageable (last 10 messages + system)
            if len(conversation) > 21:
                conversation = [conversation[0]] + conversation[-20:]

            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=conversation,  # type: ignore[arg-type]
                max_tokens=300,
                temperature=0.1,
            )

            raw: str = response.choices[0].message.content or ""
            raw = raw.strip()

            # Add assistant response to conversation history
            conversation.append({"role": "assistant", "content": raw})

            # ----------------------------------------------------------
            # Parse model response — graceful fallback on malformed JSON
            # ----------------------------------------------------------
            try:
                action_data = _extract_json(raw)
                action_type = action_data.get("action_type", "submit")
                parameters = action_data.get("parameters", {})

                # Validate action_type
                valid_actions = {
                    "search_nvd", "fetch_advisory", "lookup_gav",
                    "search_method", "scan_code", "submit",
                }
                if action_type not in valid_actions:
                    action_type = "submit"
                    parameters = {}
                    error_msg = f"Invalid action_type: {action_data.get('action_type')}"

                # Ensure parameters is a dict
                if not isinstance(parameters, dict):
                    parameters = {}

                action = CVEAction(
                    action_type=action_type,
                    parameters=parameters,
                )
            except (json.JSONDecodeError, ValueError) as parse_err:
                # Force a submit with empty params to end episode cleanly
                action = CVEAction(action_type="submit", parameters={})
                error_msg = f"Parse error: {str(parse_err)[:100]}"

            obs, reward, done, info = env.step(action)
            steps += 1
            rewards.append(reward.value)

            step_error = error_msg if error_msg != "null" else "null"
            print(
                f"[STEP] step={steps} action={action.action_type} "
                f"reward={reward.value:.2f} done={str(done).lower()} "
                f"error={step_error}"
            )

            # Reset transient error after logging
            error_msg = "null"

            if done:
                success = reward.value >= 0.5
                break

    except Exception as exc:
        error_msg = str(exc).replace("\n", " ")[:200]
        success = False
    finally:
        rewards_str = ",".join(f"{r:.2f}" for r in rewards)
        print(
            f"[END] success={str(success).lower()} "
            f"steps={steps} rewards={rewards_str}"
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Run all three tasks sequentially."""
    task_ids = [t.task_id for t in TASKS]
    for task_id in task_ids:
        run_task(task_id)


if __name__ == "__main__":
    main()
