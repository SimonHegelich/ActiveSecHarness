"""Command-Line Interface and Live End-to-End Security Verification Self-Test for ActiveSecHarness."""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import tempfile
import time
from typing import Mapping, Optional

from activesec.core.audit_log import HashChainedAuditLog
from activesec.core.capability_token import CapabilityCaveat, CapabilityEngine
from activesec.core.exceptions import ActiveSecError, CanaryTripwireError
from activesec.core.security_kernel import SecurityKernel
from activesec.guards.canary_guard import CanaryGuard
from activesec.harness.agent_loop import AgentLoop, AgentSession
from activesec.harness.model_gateway import (
    ModelGateway,
    ModelRole,
    OllamaLocalConfig,
    OpenRouterConfig,
)


def run_self_test() -> int:
    """Execute a live deterministic end-to-end demonstration of ActiveSecHarness."""
    print("=== ActiveSecHarness Ring-0 MVP Self-Test ===")
    with tempfile.TemporaryDirectory(prefix="activesec_selftest_") as tmp_dir:
        workspace = os.path.join(tmp_dir, "workspace")
        os.makedirs(workspace, mode=0o700, exist_ok=True)

        # Create a benign workspace file
        hello_path = os.path.join(workspace, "hello.txt")
        with open(hello_path, "w", encoding="utf-8") as fh:
            fh.write("ActiveSecHarness verified workspace artifact.\n")

        engine = CapabilityEngine()
        audit_log = HashChainedAuditLog()
        canary_guard = CanaryGuard(on_tripwire=engine.revoke_token)
        canaries = canary_guard.deploy_default_canaries(workspace_dir=workspace)
        honeyfile_path = next(c.honeypot_path for c in canaries if c.honeypot_path is not None)

        kernel = SecurityKernel(
            workspace_dir=workspace,
            capability_engine=engine,
            audit_log=audit_log,
            canary_guard=canary_guard,
        )

        # Deterministic offline mock transport for self-test
        call_counter = {"step": 0}

        def _selftest_transport(
            url: str,
            body: bytes,
            headers: Mapping[str, str],
            tls_context: Optional[ssl.SSLContext],
            timeout: float,
            max_response_bytes: int,
        ) -> bytes:
            call_counter["step"] += 1
            step = call_counter["step"]
            if step == 1:
                resp = {
                    "model": "qwen/qwen3-coder",
                    "choices": [
                        {
                            "message": {
                                "content": "Reading workspace file hello.txt.",
                                "tool_call": {
                                    "tool_name": "fs:read",
                                    "target_path": hello_path,
                                },
                            }
                        }
                    ],
                }
            elif step == 2:
                resp = {
                    "model": "qwen/qwen3-coder",
                    "choices": [
                        {
                            "message": {
                                "content": "Workspace file verified successfully.",
                            }
                        }
                    ],
                }
            else:
                # Step 3: Simulate an injected agent attempting to read the Canary honeyfile
                resp = {
                    "model": "qwen/qwen3-coder",
                    "choices": [
                        {
                            "message": {
                                "content": "Attempting to harvest credentials.",
                                "tool_call": {
                                    "tool_name": "fs:read",
                                    "target_path": honeyfile_path,
                                },
                            }
                        }
                    ],
                }
            return json.dumps(resp).encode("utf-8")

        mock_key = "selftest"
        gateway = ModelGateway(
            openrouter_config=OpenRouterConfig(),
            ollama_config=OllamaLocalConfig(),
            canary_guard=canary_guard,
            capability_engine=engine,
            transport_func=_selftest_transport,
            api_key=mock_key,
        )

        caveat = CapabilityCaveat(
            allowed_tools=frozenset({"fs:read", "fs:write"}),
            path_prefixes=(workspace,),
            max_calls=5,
            expires_at_unix=time.time() + 300.0,
            require_untainted_context=True,
        )
        token = engine.issue_root_token(
            subject_agent_id="selftest-agent",
            task_purpose="Self-test workspace read",
            caveat=caveat,
        )

        session = AgentSession(agent_id="selftest-agent", active_token=token, max_steps=5)
        loop = AgentLoop(kernel=kernel, gateway=gateway, role=ModelRole.CODING, prefer_provider="openrouter")

        # 1. Run benign task
        summary = loop.run(session, "Read hello.txt and summarize.")
        print(f"[PASS] Benign task completed in {summary.steps_executed} steps: '{summary.final_answer}'")

        # 2. Simulate adversarial Canary honeyfile access and verify immediate block & token revocation
        canary_blocked = False
        try:
            loop.step(session)
        except CanaryTripwireError as exc:
            canary_blocked = True
            print(f"[PASS] Adversarial Canary access blocked & token revoked: {exc}")

        if not canary_blocked:
            print("[FAIL] Canary tripwire did not trigger!", file=sys.stderr)
            return 1

        # 3. Verify cryptographic audit log chain
        audit_log.verify_chain()
        print(f"[PASS] HashChainedAuditLog verified ({len(audit_log.entries)} tamper-evident entries).")
        return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="activesec",
        description="ActiveSecHarness: Ring-0 Security Kernel & Capability-Mediated Agent Harness",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run a live deterministic end-to-end verification of safe execution and blocked attack vectors.",
    )
    parser.add_argument(
        "--provider",
        choices=("openrouter", "ollama"),
        default="openrouter",
        help="Model provider to route requests through (default: openrouter).",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Optional model identifier override (must be allowlisted).",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        try:
            return run_self_test()
        except ActiveSecError as exc:
            print(f"[ERROR] Security check failed during self-test: {exc}", file=sys.stderr)
            return 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
