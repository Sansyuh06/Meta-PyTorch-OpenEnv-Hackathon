"""
CVE-Triage-Env: Pydantic v2 typed models.

All shared data structures used across the environment are defined here.
This module imports nothing from the rest of the environment package,
ensuring zero circular-import risk.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Observation — what the agent sees after each action
# ---------------------------------------------------------------------------

class CVEObservation(BaseModel):
    """What the agent sees after each action."""

    model_config = ConfigDict(strict=False)

    cve_id: str
    step_number: int = 0
    action_history: list[str] = Field(default_factory=list)
    current_output: dict[str, Any] = Field(default_factory=dict)
    available_actions: list[str] = Field(
        default_factory=lambda: [
            "search_nvd",
            "fetch_advisory",
            "lookup_gav",
            "search_method",
            "scan_code",
            "submit",
        ]
    )
    episode_done: bool = False


# ---------------------------------------------------------------------------
# Action — what the agent wants to do
# ---------------------------------------------------------------------------

class CVEAction(BaseModel):
    """An action the agent wants to take."""

    model_config = ConfigDict(strict=False)

    action_type: Literal[
        "search_nvd",
        "fetch_advisory",
        "lookup_gav",
        "search_method",
        "scan_code",
        "submit",
    ]
    parameters: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Reward — graded feedback with a human-readable breakdown
# ---------------------------------------------------------------------------

class CVEReward(BaseModel):
    """Reward returned after each step, with a human-readable breakdown."""

    model_config = ConfigDict(strict=False)

    value: float = Field(default=0.0)
    breakdown: dict[str, float] = Field(default_factory=dict)
    message: str = ""

    @field_validator("value", mode="before")
    @classmethod
    def clamp_value(cls, v: float) -> float:
        """Clamp reward to [0.0, 1.0]."""
        return min(1.0, max(0.0, float(v)))


# ---------------------------------------------------------------------------
# Task config — definition of a single graded task
# ---------------------------------------------------------------------------

class TaskConfig(BaseModel):
    """Definition of a single graded task."""

    model_config = ConfigDict(strict=False)

    task_id: str
    name: str
    description: str
    difficulty: Literal["easy", "medium", "hard"]
    cve_id: str
    ground_truth: dict[str, Any]
    max_steps: int = 10
