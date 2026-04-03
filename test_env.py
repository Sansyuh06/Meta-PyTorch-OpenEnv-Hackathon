"""Comprehensive verification of all CVE-Triage-Env components."""

from __future__ import annotations

import sys


def main() -> None:
    passed = 0
    failed = 0

    # ──────────────────────────────────────────────────────────────────
    # Test 1: Import all modules
    # ──────────────────────────────────────────────────────────────────
    print("=== Test 1: Imports ===")
    try:
        from environment.models import CVEObservation, CVEAction, CVEReward, TaskConfig
        from environment.tasks import TASKS, get_task
        from environment.actions import ActionHandler
        from environment.graders import Grader
        from environment.env import CVETriageEnv
        from environment import CVETriageEnv as CVETriageEnv2
        assert CVETriageEnv is CVETriageEnv2, "Package re-export mismatch"
        print("  ✓ All imports OK")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1
        return  # Can't continue without imports

    # ──────────────────────────────────────────────────────────────────
    # Test 2: Pydantic v2 Models
    # ──────────────────────────────────────────────────────────────────
    print("\n=== Test 2: Pydantic v2 Models ===")
    try:
        obs = CVEObservation(cve_id="CVE-TEST", step_number=0)
        assert obs.cve_id == "CVE-TEST"
        assert len(obs.available_actions) == 6
        print(f"  ✓ CVEObservation: {obs.cve_id}, actions={len(obs.available_actions)}")

        action = CVEAction(action_type="search_nvd", parameters={})
        assert action.action_type == "search_nvd"
        print(f"  ✓ CVEAction: {action.action_type}")

        reward = CVEReward(value=0.75, breakdown={"test": 0.75}, message="ok")
        assert reward.value == 0.75
        print(f"  ✓ CVEReward: {reward.value}")

        # Test clamping (upper)
        reward2 = CVEReward(value=1.5, breakdown={}, message="clamp test")
        assert reward2.value == 1.0, f"Expected 1.0, got {reward2.value}"
        print(f"  ✓ Clamped 1.5 → {reward2.value}")

        # Test clamping (lower)
        reward3 = CVEReward(value=-0.5, breakdown={}, message="clamp test")
        assert reward3.value == 0.0, f"Expected 0.0, got {reward3.value}"
        print(f"  ✓ Clamped -0.5 → {reward3.value}")

        # Test model_dump (Pydantic v2)
        dumped = obs.model_dump()
        assert isinstance(dumped, dict)
        print(f"  ✓ model_dump() returns {type(dumped).__name__}")

        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1

    # ──────────────────────────────────────────────────────────────────
    # Test 3: Tasks
    # ──────────────────────────────────────────────────────────────────
    print("\n=== Test 3: Tasks ===")
    try:
        for t in TASKS:
            print(
                f"  ✓ {t.task_id}: {t.name} ({t.difficulty}) "
                f"- {t.cve_id}, max_steps={t.max_steps}"
            )
        assert len(TASKS) == 3, f"Expected 3 tasks, got {len(TASKS)}"

        # Test error handling
        try:
            get_task("nonexistent")
            assert False, "Should have raised ValueError"
        except ValueError as e:
            print(f"  ✓ get_task error handling OK: {e}")

        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1

    # ──────────────────────────────────────────────────────────────────
    # Test 4: Fixtures
    # ──────────────────────────────────────────────────────────────────
    print("\n=== Test 4: ActionHandler + Fixtures ===")
    try:
        handler = ActionHandler()
        assert len(handler.fixtures) == 4, f"Expected 4 fixtures, got {len(handler.fixtures)}"
        print(f"  ✓ Loaded {len(handler.fixtures)} fixtures")

        required_keys = {
            "nvd_data", "advisory_data", "gav_data", "method_data",
            "patch_diff", "synthetic_code_snippet", "ground_truth",
        }
        for cve_id, data in handler.fixtures.items():
            keys = set(data.keys())
            missing = required_keys - keys
            assert not missing, f"Missing keys in {cve_id}: {missing}"
            # Verify ground_truth.invoked is bool
            invoked = data["ground_truth"]["invoked"]
            assert isinstance(invoked, bool), (
                f"{cve_id}: ground_truth.invoked is {type(invoked).__name__}, expected bool"
            )
            print(f"  ✓ {cve_id}: {len(keys)} keys, invoked={invoked} (bool)")

        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1

    # ──────────────────────────────────────────────────────────────────
    # Test 5: Easy task dry-run
    # ──────────────────────────────────────────────────────────────────
    print("\n=== Test 5: Easy Task Dry-Run ===")
    try:
        env = CVETriageEnv("easy")
        obs = env.reset()
        assert obs.cve_id == "CVE-2022-42889"
        assert obs.step_number == 0
        assert not obs.episode_done
        print(f"  ✓ Reset: cve_id={obs.cve_id}, step={obs.step_number}")

        obs, reward, done, info = env.step(CVEAction(action_type="search_nvd"))
        assert reward.value == 0.05
        assert not done
        print(f"  ✓ Step 1 (search_nvd): reward={reward.value:.2f}")

        obs, reward, done, info = env.step(CVEAction(action_type="lookup_gav"))
        assert reward.value == 0.05
        print(f"  ✓ Step 2 (lookup_gav): reward={reward.value:.2f}")

        obs, reward, done, info = env.step(CVEAction(
            action_type="submit",
            parameters={
                "group": "org.apache.commons",
                "artifact": "commons-text",
                "safe_version": "1.10.0",
            }
        ))
        assert done
        assert reward.value == 0.9, f"Expected 0.9, got {reward.value}"
        print(f"  ✓ Step 3 (submit): reward={reward.value:.2f}")
        print(f"    Breakdown: {reward.breakdown}")

        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1

    # ──────────────────────────────────────────────────────────────────
    # Test 6: Medium task dry-run
    # ──────────────────────────────────────────────────────────────────
    print("\n=== Test 6: Medium Task Dry-Run ===")
    try:
        env2 = CVETriageEnv("medium")
        obs = env2.reset()
        for act_type in ["search_nvd", "fetch_advisory", "search_method"]:
            obs, reward, done, info = env2.step(CVEAction(action_type=act_type))
            print(f"  ✓ {act_type}: reward={reward.value:.2f}")

        obs, reward, done, info = env2.step(CVEAction(
            action_type="submit",
            parameters={
                "group": "org.apache.logging.log4j",
                "artifact": "log4j-core",
                "vulnerable_method": "lookup",
                "safe_version": "2.15.0",
            }
        ))
        assert done
        assert reward.value == 1.0, f"Expected 1.0, got {reward.value}"
        print(f"  ✓ submit: reward={reward.value:.2f}")
        print(f"    Breakdown: {reward.breakdown}")

        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1

    # ──────────────────────────────────────────────────────────────────
    # Test 7: Hard task dry-run (perfect run)
    # ──────────────────────────────────────────────────────────────────
    print("\n=== Test 7: Hard Task Dry-Run ===")
    try:
        env3 = CVETriageEnv("hard")
        obs = env3.reset()
        for act_type in ["search_nvd", "fetch_advisory", "lookup_gav", "search_method", "scan_code"]:
            obs, reward, done, info = env3.step(CVEAction(action_type=act_type))
            print(f"  ✓ {act_type}: reward={reward.value:.2f}")

        obs, reward, done, info = env3.step(CVEAction(
            action_type="submit",
            parameters={
                "group": "org.springframework",
                "artifact": "spring-webmvc",
                "vulnerable_method": "bind",
                "invoked": False,
                "safe_version": "5.3.18",
            }
        ))
        assert done
        assert reward.value == 1.0, f"Expected 1.0, got {reward.value}"
        print(f"  ✓ submit: reward={reward.value:.2f}")
        print(f"    Breakdown: {reward.breakdown}")

        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1

    # ──────────────────────────────────────────────────────────────────
    # Test 8: state() returns all required keys
    # ──────────────────────────────────────────────────────────────────
    print("\n=== Test 8: state() ===")
    try:
        state = env3.state()
        required_state_keys = {"task_id", "cve_id", "step_number", "action_history", "episode_done"}
        assert required_state_keys == set(state.keys()), (
            f"Missing keys: {required_state_keys - set(state.keys())}"
        )
        print(f"  ✓ State keys: {sorted(state.keys())}")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1

    # ──────────────────────────────────────────────────────────────────
    # Test 9: RuntimeError on step after done
    # ──────────────────────────────────────────────────────────────────
    print("\n=== Test 9: Episode-done Guard ===")
    try:
        try:
            env3.step(CVEAction(action_type="search_nvd"))
            assert False, "Should have raised RuntimeError"
        except RuntimeError as e:
            print(f"  ✓ Correctly raised RuntimeError: {e}")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1

    # ──────────────────────────────────────────────────────────────────
    # Test 10: Max-step timeout
    # ──────────────────────────────────────────────────────────────────
    print("\n=== Test 10: Max-step Timeout ===")
    try:
        env4 = CVETriageEnv("easy")
        env4.reset()
        for i in range(5):
            obs, reward, done, info = env4.step(CVEAction(action_type="search_nvd"))
            if done:
                print(f"  ✓ Episode timed out at step {i + 1}: reward={reward.value:.2f}")
                print(f"    Message: {reward.message}")
                break
        assert done, "Should have timed out by step 5"
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1

    # ──────────────────────────────────────────────────────────────────
    # Test 11: FastAPI app import
    # ──────────────────────────────────────────────────────────────────
    print("\n=== Test 11: FastAPI App Import ===")
    try:
        from app import app
        print(f"  ✓ App title: {app.title}")
        routes = [r.path for r in app.routes if hasattr(r, "path")]
        print(f"  ✓ Routes: {routes}")
        required_routes = {"/reset", "/step", "/state", "/tasks", "/health"}
        actual_routes = set(routes)
        missing_routes = required_routes - actual_routes
        assert not missing_routes, f"Missing routes: {missing_routes}"
        print(f"  ✓ All required routes present")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1

    # ──────────────────────────────────────────────────────────────────
    # Test 12: Grader edge cases
    # ──────────────────────────────────────────────────────────────────
    print("\n=== Test 12: Grader Edge Cases ===")
    try:
        grader = Grader()

        # Test wrong submission for easy task
        easy_task = get_task("easy")
        r = grader.grade(easy_task, {}, ["submit"])
        # Empty submission: efficiency_bonus +0.2 (1 step ≤ 4) - early_submit_penalty -0.1 = 0.1
        assert r.value == 0.1, f"Expected 0.1 for empty submission, got {r.value}"
        print(f"  ✓ Empty submission: reward={r.value:.2f} (efficiency - penalty)")

        # Test partial submission
        r2 = grader.grade(
            easy_task,
            {"group": "org.apache.commons", "artifact": "commons-text"},
            ["search_nvd", "submit"],
        )
        assert abs(r2.value - 0.6) < 1e-9, f"Expected ~0.6 for partial, got {r2.value}"
        print(f"  ✓ Partial submission (GAV only): reward={r2.value:.2f}")

        # Test string "true"/"false" handling for invoked field
        hard_task = get_task("hard")
        r3 = grader.grade(
            hard_task,
            {
                "group": "org.springframework",
                "artifact": "spring-webmvc",
                "vulnerable_method": "bind",
                "invoked": "false",  # String, not bool
                "safe_version": "5.3.18",
            },
            ["search_nvd", "fetch_advisory", "lookup_gav", "search_method", "scan_code", "submit"],
        )
        assert r3.breakdown["invocation_correct"] == 0.30, (
            f"String 'false' should match bool False, got {r3.breakdown}"
        )
        print(f"  ✓ String 'false' handled as bool: invocation_correct=0.30")

        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1

    # ──────────────────────────────────────────────────────────────────
    # Summary
    # ──────────────────────────────────────────────────────────────────
    print()
    print("═" * 50)
    total = passed + failed
    if failed == 0:
        print(f"  ✓ ALL {total} TESTS PASSED")
    else:
        print(f"  {passed}/{total} passed, {failed} FAILED")
    print("═" * 50)

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
