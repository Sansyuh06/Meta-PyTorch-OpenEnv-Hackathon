"""Test all FastAPI API endpoints using httpx TestClient (no live server needed)."""

from __future__ import annotations

import sys
from fastapi.testclient import TestClient
from app import app


def main() -> None:
    """Run all API tests using the FastAPI TestClient."""
    # Use context manager so lifespan startup/shutdown fires
    with TestClient(app) as client:
        _run_tests(client)


def _run_tests(client: TestClient) -> None:
    passed = 0
    failed = 0

    # ──────────────────────────────────────────────────────────────────
    # Test 1: Health check
    # ──────────────────────────────────────────────────────────────────
    print("=== API Test 1: Health ===")
    try:
        r = client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["version"] == "1.0.0"
        print(f"  ✓ GET /health: {r.status_code} {data}")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1

    # ──────────────────────────────────────────────────────────────────
    # Test 2: List tasks
    # ──────────────────────────────────────────────────────────────────
    print("\n=== API Test 2: Tasks ===")
    try:
        r = client.get("/tasks")
        assert r.status_code == 200
        tasks = r.json()
        assert len(tasks) == 3
        for t in tasks:
            print(f"  ✓ {t['task_id']}: {t['name']}")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1

    # ──────────────────────────────────────────────────────────────────
    # Test 3: Reset
    # ──────────────────────────────────────────────────────────────────
    print("\n=== API Test 3: Reset ===")
    try:
        r = client.post("/reset", json={"task_id": "easy"})
        assert r.status_code == 200
        obs = r.json()
        assert obs["cve_id"] == "CVE-2022-42889"
        assert obs["episode_done"] is False
        print(f"  ✓ POST /reset: cve_id={obs['cve_id']}, done={obs['episode_done']}")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1

    # ──────────────────────────────────────────────────────────────────
    # Test 4: Step (search_nvd)
    # ──────────────────────────────────────────────────────────────────
    print("\n=== API Test 4: Step (search_nvd) ===")
    try:
        r = client.post("/step", json={"action_type": "search_nvd", "parameters": {}})
        assert r.status_code == 200
        data = r.json()
        assert data["done"] is False
        assert data["reward"]["value"] == 0.05
        print(f"  ✓ POST /step: reward={data['reward']['value']}, done={data['done']}")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1

    # ──────────────────────────────────────────────────────────────────
    # Test 5: Step (submit with correct answer)
    # ──────────────────────────────────────────────────────────────────
    print("\n=== API Test 5: Step (submit) ===")
    try:
        r = client.post("/step", json={
            "action_type": "submit",
            "parameters": {
                "group": "org.apache.commons",
                "artifact": "commons-text",
                "safe_version": "1.10.0",
            }
        })
        assert r.status_code == 200
        data = r.json()
        assert data["done"] is True
        print(f"  ✓ POST /step submit: reward={data['reward']['value']}, done={data['done']}")
        print(f"    Breakdown: {data['reward']['breakdown']}")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1

    # ──────────────────────────────────────────────────────────────────
    # Test 6: State
    # ──────────────────────────────────────────────────────────────────
    print("\n=== API Test 6: State ===")
    try:
        r = client.get("/state")
        assert r.status_code == 200
        state = r.json()
        assert "task_id" in state
        assert "episode_done" in state
        print(f"  ✓ GET /state: {state}")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1

    # ──────────────────────────────────────────────────────────────────
    # Test 7: Step after done (should 400)
    # ──────────────────────────────────────────────────────────────────
    print("\n=== API Test 7: Step After Done ===")
    try:
        r = client.post("/step", json={"action_type": "search_nvd", "parameters": {}})
        assert r.status_code == 400, f"Expected 400, got {r.status_code}"
        print(f"  ✓ POST /step after done: {r.status_code} (correctly rejected)")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1

    # ──────────────────────────────────────────────────────────────────
    # Test 8: Reset to different task
    # ──────────────────────────────────────────────────────────────────
    print("\n=== API Test 8: Reset to Hard ===")
    try:
        r = client.post("/reset", json={"task_id": "hard"})
        assert r.status_code == 200
        obs = r.json()
        assert obs["cve_id"] == "CVE-2022-22965"
        print(f"  ✓ POST /reset hard: cve_id={obs['cve_id']}")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1

    # ──────────────────────────────────────────────────────────────────
    # Test 9: Invalid task ID
    # ──────────────────────────────────────────────────────────────────
    print("\n=== API Test 9: Invalid Task ===")
    try:
        r = client.post("/reset", json={"task_id": "nonexistent"})
        assert r.status_code == 400, f"Expected 400, got {r.status_code}"
        print(f"  ✓ POST /reset invalid: {r.status_code} (correctly rejected)")
        passed += 1
    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        failed += 1

    # ──────────────────────────────────────────────────────────────────
    # Test 10: Full episode via API (hard task)
    # ──────────────────────────────────────────────────────────────────
    print("\n=== API Test 10: Full Hard Episode ===")
    try:
        # Reset to hard
        r = client.post("/reset", json={"task_id": "hard"})
        assert r.status_code == 200

        # Run all investigation actions
        for action in ["search_nvd", "fetch_advisory", "lookup_gav", "search_method", "scan_code"]:
            r = client.post("/step", json={"action_type": action, "parameters": {}})
            assert r.status_code == 200
            assert r.json()["done"] is False

        # Submit perfect answer
        r = client.post("/step", json={
            "action_type": "submit",
            "parameters": {
                "group": "org.springframework",
                "artifact": "spring-webmvc",
                "vulnerable_method": "bind",
                "invoked": False,
                "safe_version": "5.3.18",
            }
        })
        assert r.status_code == 200
        data = r.json()
        assert data["done"] is True
        assert data["reward"]["value"] == 1.0, f"Expected 1.0, got {data['reward']['value']}"
        print(f"  ✓ Full hard episode: reward={data['reward']['value']:.2f}")
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
        print(f"  ✓ ALL {total} API TESTS PASSED")
    else:
        print(f"  {passed}/{total} passed, {failed} FAILED")
    print("═" * 50)

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
