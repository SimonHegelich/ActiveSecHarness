"""Ring-0 SecurityKernel: Deterministic Reference Monitor & Tool Call Mediator.

Every tool invocation requested by an agent in Ring 2/3 must pass through SecurityKernel:
1. CanaryGuard inspection on target paths, commands, and arguments (instant token revocation on tripwire).
2. CapabilityEngine cryptographic token verification (HMAC chain, attenuation, TTL, quota, path prefix, taint lock).
3. CommandDeobfuscator inspection for Trojan Source Unicode, Base64/Hex obfuscation, and LotL traps.
4. Deterministic Guard dispatch (`fs:read`, `fs:write`, `archive:extract`, `shell:exec`, `net:https`).
5. HashChainedAuditLog recording of every allowed and blocked security event.
"""

from __future__ import annotations

import os
import shlex
import shutil
import urllib.parse
from dataclasses import dataclass
from typing import Optional

from activesec.core.audit_log import HashChainedAuditLog
from activesec.core.capability_token import (
    CapabilityEngine,
    CapabilityToken,
    InformationClass,
)
from activesec.core.component import ComponentSecurityAssessment, SecureComponent
from activesec.core.exceptions import (
    ActiveSecError,
    CanaryTripwireError,
    CapabilityViolationError,
)
from activesec.core.sod_policy import WorkspaceProvenanceLedger
from activesec.core.tool_registry import CertifiedToolRegistry
from activesec.core.wiki_manager import RuntimeTelemetrySnapshot, WikiManager
from activesec.guards.archive_guard import ArchiveGuard
from activesec.guards.canary_guard import CanaryGuard
from activesec.guards.credential_guard import CredentialGuard
from activesec.guards.malware_guard import MalwareGuard
from activesec.guards.network_guard import NetworkGuard
from activesec.guards.sandbox_guard import SandboxGuard
from activesec.harness.model_gateway import ToolCallRequest
from activesec.sovereign.deobfuscator import CommandDeobfuscator


@dataclass(frozen=True, slots=True)
class ToolExecutionResult:
    """Immutable result of a kernel-mediated tool execution."""

    tool_name: str
    output: str
    sanitized: bool
    audit_sequence_id: int


class SecurityKernel(SecureComponent):
    """Ring-0 reference monitor mediating all agent tool requests across security guards."""

    def __init__(
        self,
        *,
        workspace_dir: str,
        capability_engine: Optional[CapabilityEngine] = None,
        audit_log: Optional[HashChainedAuditLog] = None,
        canary_guard: Optional[CanaryGuard] = None,
        credential_guard: Optional[CredentialGuard] = None,
        malware_guard: Optional[MalwareGuard] = None,
        archive_guard: Optional[ArchiveGuard] = None,
        network_guard: Optional[NetworkGuard] = None,
        sandbox_guard: Optional[SandboxGuard] = None,
        deobfuscator: Optional[CommandDeobfuscator] = None,
        wiki_manager: Optional[WikiManager] = None,
        tool_registry: Optional[CertifiedToolRegistry] = None,
        provenance_ledger: Optional[WorkspaceProvenanceLedger] = None,
    ) -> None:
        self._workspace_dir: str = os.path.realpath(workspace_dir)
        os.makedirs(self._workspace_dir, mode=0o700, exist_ok=True)

        self._capability_engine: CapabilityEngine = capability_engine or CapabilityEngine()
        self._audit_log: HashChainedAuditLog = audit_log or HashChainedAuditLog()
        self._canary_guard: CanaryGuard = canary_guard or CanaryGuard(
            on_tripwire=self._capability_engine.revoke_token
        )
        if self._canary_guard._on_tripwire is None:
            self._canary_guard._on_tripwire = self._capability_engine.revoke_token

        self._credential_guard: CredentialGuard = credential_guard or CredentialGuard()
        self._malware_guard: MalwareGuard = malware_guard or MalwareGuard()
        self._archive_guard: ArchiveGuard = archive_guard or ArchiveGuard()
        self._network_guard: NetworkGuard = network_guard or NetworkGuard()
        self._sandbox_guard: SandboxGuard = sandbox_guard or SandboxGuard()
        self._deobfuscator: CommandDeobfuscator = deobfuscator or CommandDeobfuscator()
        self._wiki_manager: WikiManager = wiki_manager or WikiManager()
        self._tool_registry: Optional[CertifiedToolRegistry] = tool_registry
        self._provenance_ledger: WorkspaceProvenanceLedger = (
            provenance_ledger or WorkspaceProvenanceLedger(workspace_dir=self._workspace_dir)
        )

    @classmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        return ComponentSecurityAssessment(
            component_id="security_kernel",
            title="Ring-0 Security Kernel & Complete Mediation Reference Monitor",
            ring_level=0,
            source_path="src/activesec/core/security_kernel.py",
            security_test_path="tests/security/test_sec_security_kernel.py",
            threat_vectors=("A.1", "A.3", "A.4", "B.1", "B.2", "B.3", "B.4", "C.1", "C.2", "C.3", "D.2", "E.1", "F.1", "F.2", "F.3"),
            summary=(
                "Acts as the non-bypassable Ring-0 reference monitor between the agent loop and "
                "host resources. Enforces CanaryGuard tripwire checks, CapabilityToken verification, "
                "CommandDeobfuscator inspection, deterministic guard dispatch (CredentialGuard, "
                "MalwareGuard, ArchiveGuard, NetworkGuard, SandboxGuard), and tamper-evident "
                "HashChainedAuditLog recording on every single tool request."
            ),
            enforced_invariants=(
                "Evaluates CanaryGuard tripwires on target paths, raw commands, and arguments before touching any resource, revoking the active token on violation.",
                "Verifies CapabilityToken signatures, revocation state, TTL, call quota, path confinement, allowed binaries, and 5-level InformationClass taint lattice via CapabilityEngine.",
                "Enforces Compositional Cross-Agent Separation of Duties via WorkspaceProvenanceLedger, tracking per-file provenance labels l(f) on workspace writes and propagating taint/sensitivity across collaborating agents.",
                "Runs CommandDeobfuscator.inspect_command(..., fail_on_critical=True) on all shell:exec requests and rejects shell=True.",
                "Scans files with MalwareGuard before fs:read or after fs:write/archive:extract, and enforces CredentialGuard DLP on both read (redaction) and write (blocking).",
                "Appends an immutable, cryptographically signed AuditLogEntry for every allowed or blocked tool invocation.",
            ),
            residual_risks=(
                "Logic bugs within an explicitly authorized workspace script executed inside the sandbox (mitigated by bubblewrap namespace isolation and offline network default).",
            ),
        )

    @property
    def workspace_dir(self) -> str:
        return self._workspace_dir

    @property
    def capability_engine(self) -> CapabilityEngine:
        return self._capability_engine

    @property
    def audit_log(self) -> HashChainedAuditLog:
        return self._audit_log

    @property
    def canary_guard(self) -> CanaryGuard:
        return self._canary_guard

    @property
    def wiki_manager(self) -> WikiManager:
        return self._wiki_manager

    @property
    def tool_registry(self) -> Optional[CertifiedToolRegistry]:
        return self._tool_registry

    @property
    def provenance_ledger(self) -> WorkspaceProvenanceLedger:
        return self._provenance_ledger

    def sync_runtime_wiki(
        self,
        *,
        session_label: str = "kernel_runtime",
        execute_pytest: bool = False,
        quiet: bool = True,
    ) -> RuntimeTelemetrySnapshot:
        """Synchronize runtime telemetry from the kernel's HashChainedAuditLog into the Karpathy Wiki."""
        self._wiki_manager.sync_all(
            execute_pytest=execute_pytest,
            audit_log=self._audit_log,
            session_label=session_label,
            quiet=quiet,
        )
        return self._wiki_manager.telemetry_history[-1]

    def execute_tool_call(
        self,
        request: ToolCallRequest,
        *,
        token: CapabilityToken,
        agent_id: str,
        context_tainted: bool = False,
        information_class: Optional[InformationClass] = None,
        call_nonce: Optional[str] = None,
        current_time: Optional[float] = None,
    ) -> ToolExecutionResult:
        """Mediate and execute a single ToolCallRequest through all Ring-0 guards."""
        target_path = request.target_path or request.arguments.get("path") or request.arguments.get("target_path") or request.arguments.get("zip_path")
        raw_command = request.raw_command or request.arguments.get("command") or request.arguments.get("raw_command")
        net_dest = request.network_destination
        url_arg = request.arguments.get("url")
        if net_dest is None and url_arg:
            parsed_url = urllib.parse.urlsplit(url_arg)
            if parsed_url.hostname:
                net_dest = parsed_url.hostname.lower()

        binary_name = request.binary_name
        parsed_argv: list[str] = []
        if request.tool_name == "shell:exec":
            if not raw_command or not raw_command.strip():
                err = CapabilityViolationError(
                    "shell:exec requires a non-empty command.",
                    vector_id="A.1",
                    component_id="security_kernel",
                )
                self._record_blocked_event(request, token=token, agent_id=agent_id, error=err)
                raise err
            try:
                # Step 3 pre-parse check for Trojan Source / obfuscation before shlex
                self._canary_guard.check_stream_for_canaries(raw_command, active_token_id=token.token_id)
                self._deobfuscator.inspect_command(raw_command, fail_on_critical=True)
                parsed_argv = shlex.split(raw_command)
            except ActiveSecError as exc:
                if isinstance(exc, CanaryTripwireError):
                    self._capability_engine.revoke_token(token.token_id)
                self._record_blocked_event(request, token=token, agent_id=agent_id, error=exc)
                raise
            except ValueError as exc:
                err = CapabilityViolationError(
                    f"Malformed shell command syntax: {exc}",
                    vector_id="A.1",
                    component_id="security_kernel",
                )
                self._record_blocked_event(request, token=token, agent_id=agent_id, error=err)
                raise err from exc

            if not parsed_argv:
                err = CapabilityViolationError(
                    "Parsed shell command produced empty argv.",
                    vector_id="A.1",
                    component_id="security_kernel",
                )
                self._record_blocked_event(request, token=token, agent_id=agent_id, error=err)
                raise err
            if binary_name is None:
                binary_name = os.path.basename(parsed_argv[0])

        try:
            # 1. CanaryGuard inspection on target path and arguments
            if target_path is not None:
                self._canary_guard.check_path_access(target_path, active_token_id=token.token_id)
            if raw_command is not None:
                self._canary_guard.check_stream_for_canaries(raw_command, active_token_id=token.token_id)
            for arg_val in request.arguments.values():
                self._canary_guard.check_stream_for_canaries(str(arg_val), active_token_id=token.token_id)
            if request.tool_name == "shell:exec":
                for tok in parsed_argv[1:]:
                    if "/" in tok or tok.startswith("."):
                        candidate = tok if os.path.isabs(tok) else os.path.join(self._workspace_dir, tok)
                        self._canary_guard.check_path_access(candidate, active_token_id=token.token_id)

            # 2. Verify CapabilityToken & 5-level IFC lattice via CapabilityEngine
            agent_flow = self._provenance_ledger.get_agent_state(agent_id)
            effective_info_class = information_class
            if effective_info_class is None and agent_flow.information_class in (
                InformationClass.DERIVED,
                InformationClass.UNTRUSTED,
            ):
                effective_info_class = agent_flow.information_class

            self._capability_engine.verify_tool_call(
                token=token,
                agent_id=agent_id,
                tool_name=request.tool_name,
                target_path=target_path,
                binary_name=binary_name,
                raw_command=raw_command,
                network_destination=net_dest,
                context_tainted=context_tainted,
                information_class=effective_info_class,
                call_nonce=call_nonce,
                current_time=current_time,
            )

            # 3. Verify Compositional Workspace Provenance SoD (cross-agent IFC)
            self._provenance_ledger.verify_compositional_action(
                agent_id=agent_id,
                tool_name=request.tool_name,
                target_path=target_path,
                binary_name=binary_name,
                raw_command=raw_command,
                explicit_information_class=information_class,
            )

            # 4. Verify Tool Certification, Agent-Tool Qualification & Combinatorial SoD Policy
            if self._tool_registry is not None:
                self._tool_registry.enforce_tool_call(
                    request,
                    agent_id=agent_id,
                    session_key=f"{agent_id}:{token.token_id}",
                    current_time=current_time,
                )

            # 5. Dispatch to deterministic guards based on tool_name
            output, sanitized = self._dispatch_tool(
                request=request,
                token=token,
                agent_id=agent_id,
                target_path=target_path,
                parsed_argv=parsed_argv,
                information_class=information_class,
            )

        except ActiveSecError as exc:
            if isinstance(exc, CanaryTripwireError):
                self._capability_engine.revoke_token(token.token_id)
            self._record_blocked_event(request, token=token, agent_id=agent_id, error=exc)
            raise

        # 5. Record allowed action in HashChainedAuditLog
        entry = self._audit_log.append_event(
            event_type="TOOL_CALL_ALLOWED",
            actor_id=agent_id,
            ring_level=token.issuer_ring,
            vector_id="NONE",
            details={
                "sanitized": str(sanitized),
                "target_path": str(target_path or ""),
                "token_id": token.token_id,
                "tool_name": request.tool_name,
            },
        )
        return ToolExecutionResult(
            tool_name=request.tool_name,
            output=output,
            sanitized=sanitized,
            audit_sequence_id=entry.sequence_id,
        )

    def _record_blocked_event(
        self,
        request: ToolCallRequest,
        *,
        token: CapabilityToken,
        agent_id: str,
        error: ActiveSecError,
    ) -> None:
        event_type = "CANARY_TRIPWIRE_ALERT" if isinstance(error, CanaryTripwireError) else "TOOL_CALL_BLOCKED"
        ring = token.issuer_ring if token.issuer_ring in (0, 1, 2, 3) else 2
        self._audit_log.append_event(
            event_type=event_type,
            actor_id=agent_id or "unknown_agent",
            ring_level=ring,
            vector_id=error.vector_id,
            details={
                "component_id": error.component_id,
                "reason": error.message,
                "token_id": token.token_id,
                "tool_name": request.tool_name,
            },
        )

    def _dispatch_tool(
        self,
        *,
        request: ToolCallRequest,
        token: CapabilityToken,
        agent_id: str,
        target_path: Optional[str],
        parsed_argv: list[str],
        information_class: Optional[InformationClass] = None,
    ) -> tuple[str, bool]:
        if request.tool_name == "fs:read":
            if not target_path:
                raise CapabilityViolationError(
                    "fs:read requires a target_path.",
                    vector_id="A.3",
                    component_id="security_kernel",
                )
            real_path = os.path.realpath(target_path)
            self._malware_guard.scan_file(real_path)
            with open(real_path, "r", encoding="utf-8", errors="replace") as fh:
                raw_text = fh.read()
            self._canary_guard.check_stream_for_canaries(raw_text, active_token_id=token.token_id)
            redacted = self._credential_guard.redact_secrets(raw_text)
            was_redacted = redacted != raw_text
            inferred_class = information_class
            if inferred_class is None and was_redacted:
                inferred_class = InformationClass.SENSITIVE
            self._provenance_ledger.record_file_read(
                agent_id=agent_id,
                path=real_path,
                explicit_file_class=inferred_class,
            )
            return (redacted, was_redacted)

        if request.tool_name == "fs:write":
            if not target_path:
                raise CapabilityViolationError(
                    "fs:write requires a target_path.",
                    vector_id="A.3",
                    component_id="security_kernel",
                )
            content = str(request.arguments.get("content", ""))
            self._canary_guard.check_stream_for_canaries(content, active_token_id=token.token_id)
            self._credential_guard.assert_no_cleartext_secrets(content)

            real_path = os.path.realpath(target_path)
            os.makedirs(os.path.dirname(real_path), mode=0o700, exist_ok=True)
            with open(real_path, "w", encoding="utf-8") as fh:
                fh.write(content)
            os.chmod(real_path, 0o600)

            try:
                self._malware_guard.scan_file(real_path)
            except ActiveSecError:
                try:
                    os.unlink(real_path)
                except OSError:
                    pass
                raise
            self._provenance_ledger.record_file_write(
                agent_id=agent_id,
                path=real_path,
                content=content,
                explicit_class=information_class,
            )
            return (f"Wrote {len(content)} bytes to {real_path}", False)

        if request.tool_name == "archive:extract":
            if not target_path:
                raise CapabilityViolationError(
                    "archive:extract requires a target_path (ZIP archive path).",
                    vector_id="B.1",
                    component_id="security_kernel",
                )
            dest_dir = request.arguments.get("dest_dir") or os.path.join(self._workspace_dir, "extracted")
            real_dest = os.path.realpath(dest_dir)
            # Ensure destination directory is also inside the workspace / token path prefixes
            for caveat in token.caveats:
                real_prefixes = [os.path.realpath(p) for p in caveat.path_prefixes]
                if not any(real_dest == p or real_dest.startswith(p + os.sep) for p in real_prefixes):
                    raise CapabilityViolationError(
                        f"Archive extraction destination '{dest_dir}' is outside permitted capability prefixes.",
                        vector_id="B.2",
                        component_id="security_kernel",
                    )

            extracted_files = self._archive_guard.safe_extract_zip(target_path, real_dest)
            try:
                for ext_file in extracted_files:
                    self._malware_guard.scan_file(ext_file)
                    self._provenance_ledger.record_file_write(
                        agent_id=agent_id,
                        path=ext_file,
                        explicit_class=information_class or InformationClass.UNTRUSTED,
                    )
            except ActiveSecError:
                shutil.rmtree(real_dest, ignore_errors=True)
                raise
            return (f"Extracted and verified {len(extracted_files)} files into {real_dest}", False)

        if request.tool_name == "shell:exec":
            exec_res = self._sandbox_guard.run_sandboxed(
                parsed_argv,
                workspace_dir=self._workspace_dir,
            )
            combined_out = (exec_res.stdout + "\n" + exec_res.stderr).strip()
            self._canary_guard.check_stream_for_canaries(combined_out, active_token_id=token.token_id)
            redacted_out = self._credential_guard.redact_secrets(combined_out)
            return (redacted_out, redacted_out != combined_out)

        if request.tool_name == "net:https":
            url = request.arguments.get("url") or (
                f"https://{request.network_destination}" if request.network_destination else ""
            )
            if not url:
                raise CapabilityViolationError(
                    "net:https requires a target URL.",
                    vector_id="C.1",
                    component_id="security_kernel",
                )
            body = str(request.arguments.get("body", ""))
            self._canary_guard.check_stream_for_canaries(body, active_token_id=token.token_id)
            self._credential_guard.assert_no_cleartext_secrets(body)
            endpoint = self._network_guard.validate_url_target(url)
            return (
                f"Verified HTTPS TLS 1.3 endpoint {endpoint.hostname}:{endpoint.port} (IPs: {', '.join(endpoint.pinned_ips)})",
                False,
            )

        if self._tool_registry is not None:
            spec = self._tool_registry._tools.get(request.tool_name)
            if spec is not None and spec.handler is not None:
                raw_out = str(spec.handler(request.arguments))
                self._canary_guard.check_stream_for_canaries(raw_out, active_token_id=token.token_id)
                redacted = self._credential_guard.redact_secrets(raw_out)
                return (redacted, redacted != raw_out)

        raise CapabilityViolationError(
            f"Unsupported or unknown tool type '{request.tool_name}'.",
            vector_id="A.1",
            component_id="security_kernel",
        )
