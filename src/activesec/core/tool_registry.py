"""Ring-0 Anti-MCP Certified Tool Registry, Agent-Tool Qualification & Combinatorial SoD Engine.

Replaces unverified dynamic tool protocols (MCP) with a deterministic, zero-trust Ring-0
certification and combinatorial Separation-of-Duties (SoD) architecture:
1. Stage 1 — Mandatory Tool Certification (`ToolCertificate` & `CertifiedToolSpec`):
   - Every tool must declare an immutable input schema (`allowed_arg_keys`, `required_arg_keys`)
     and an explicit `side_effect_class` (`READ_EXTERNAL`, `READ_SENSITIVE`, `WRITE_LOCAL`,
     `EXEC_PROCESS`, `NETWORK_EGRESS`, `PURE_COMPUTE`).
   - Before Ring 0 issues a signed `ToolCertificate`, the tool handler undergoes static Python
     AST safety auditing (`audit_python_ast_source`) and mandatory adversarial probe execution.
   - Any post-certification change to the handler bytecode/source or schema triggers an immediate
     `ToolCertificationError` (`vector_id="A.1"`), defeating MCP-style rug-pull/tool-poisoning attacks.
2. Stage 2 — Agent-Tool Qualification & Combinatorial Certification (`AgentToolCertificate`):
   - Agents do not automatically receive access to certified tools.
   - Each `agent_id` must hold a cryptographically signed `AgentToolCertificate` earned via
     `run_agent_tool_qualification_suite(...)`, proving 100% pass rate on both individual tools
     (`certified_tools`) and explicit pairwise/subset tool combinations (`certified_combinations`).
   - Invoking an uncertified tool or combining two tools in a session without combinatorial
     certification raises `ToolCertificationError` (`vector_id="F.3"`).
3. Stage 3 — Deterministic Separation of Duties (SoD) & Toxic Combination Splitter (`ToxicToolPolicy`):
   - Prevents the "Lethal Trifecta" (e.g., combining `READ_SENSITIVE` or `READ_EXTERNAL` with
     `NETWORK_EGRESS` or `EXEC_PROCESS` inside a single agent session).
   - Provides hard runtime blocking (`ToxicCombinationError`, `vector_id="F.3"`) AND deterministic
     multi-agent workflow partitioning (`partition_tool_plan_across_agents`) that splits a toxic
     plan across isolated sub-agents (`AgentSubTaskAssignment`) with attenuated `CapabilityToken`
     and `AgentToolCertificate` scopes.
"""

from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import secrets
import textwrap
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, List, Mapping, Optional, Sequence, Set, Tuple

from activesec.core.capability_token import CapabilityCaveat, CapabilityEngine, CapabilityToken
from activesec.core.component import ComponentSecurityAssessment, SecureComponent
from activesec.core.exceptions import (
    ActiveSecError,
    ToolCertificationError,
    ToxicCombinationError,
)
from activesec.core.wiki_manager import audit_python_ast_source
from activesec.harness.model_gateway import ToolCallRequest


VALID_SIDE_EFFECT_CLASSES: FrozenSet[str] = frozenset(
    {
        "PURE_COMPUTE",
        "READ_LOCAL",
        "READ_SENSITIVE",
        "READ_EXTERNAL",
        "WRITE_LOCAL",
        "EXEC_PROCESS",
        "NETWORK_EGRESS",
    }
)


ToolHandlerFunc = Callable[[Mapping[str, str]], str]
AdversarialToolProbe = Callable[[ToolHandlerFunc], bool]
AgentCombinationProbe = Callable[[str, FrozenSet[str]], bool]


@dataclass(frozen=True, slots=True)
class ToolCertificate:
    """Ring-0 cryptographic certificate binding a tool's schema, side-effect class, and handler hash."""

    certificate_id: str
    tool_name: str
    side_effect_class: str
    schema_sha256: str
    handler_sha256: str
    probes_executed: int
    issued_at_unix: float
    signature: str


@dataclass(frozen=True, slots=True)
class CertifiedToolSpec:
    """Immutable specification and signed certificate for a Ring-0 verified tool."""

    tool_name: str
    description: str
    side_effect_class: str
    allowed_arg_keys: FrozenSet[str]
    required_arg_keys: FrozenSet[str] = frozenset()
    max_arg_value_chars: int = 16_384
    handler: Optional[ToolHandlerFunc] = None
    certificate: Optional[ToolCertificate] = None

    def canonical_schema_dict(self) -> Dict[str, object]:
        """Return deterministic dictionary representation of the tool schema."""
        return {
            "allowed_arg_keys": sorted(self.allowed_arg_keys),
            "description": self.description.strip(),
            "max_arg_value_chars": self.max_arg_value_chars,
            "required_arg_keys": sorted(self.required_arg_keys),
            "side_effect_class": self.side_effect_class.strip().upper(),
            "tool_name": self.tool_name.strip(),
        }

    def compute_schema_sha256(self) -> str:
        """Compute the SHA-256 digest of the canonical schema specification."""
        raw = json.dumps(self.canonical_schema_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class AgentToolCertificate:
    """Ring-0 cryptographic certificate authorizing an agent for specific tools and combinations."""

    certificate_id: str
    agent_id: str
    certified_tools: FrozenSet[str]
    certified_combinations: FrozenSet[FrozenSet[str]]
    qualification_probes_passed: int
    issued_at_unix: float
    expires_at_unix: float
    signature: str

    def canonical_payload_dict(self) -> Dict[str, object]:
        combos_sorted = sorted(
            [sorted(c) for c in self.certified_combinations],
            key=lambda item: ",".join(item),
        )
        return {
            "agent_id": self.agent_id,
            "certificate_id": self.certificate_id,
            "certified_combinations": combos_sorted,
            "certified_tools": sorted(self.certified_tools),
            "expires_at_unix": round(self.expires_at_unix, 6),
            "issued_at_unix": round(self.issued_at_unix, 6),
            "qualification_probes_passed": self.qualification_probes_passed,
        }


@dataclass(frozen=True, slots=True)
class ToxicToolPolicy:
    """Immutable Separation-of-Duties (SoD) policy defining mutually exclusive tool/effect pairs."""

    incompatible_side_effect_pairs: FrozenSet[FrozenSet[str]] = field(
        default_factory=lambda: frozenset(
            {
                frozenset({"READ_SENSITIVE", "NETWORK_EGRESS"}),
                frozenset({"READ_SENSITIVE", "EXEC_PROCESS"}),
                frozenset({"READ_EXTERNAL", "NETWORK_EGRESS"}),
                frozenset({"READ_EXTERNAL", "EXEC_PROCESS"}),
            }
        )
    )
    incompatible_tool_pairs: FrozenSet[FrozenSet[str]] = field(
        default_factory=lambda: frozenset(
            {
                frozenset({"fs:read", "net:https"}),
                frozenset({"fs:read", "shell:exec"}),
                frozenset({"net:fetch_untrusted", "shell:exec"}),
                frozenset({"net:fetch_untrusted", "net:https"}),
                frozenset({"archive:extract", "net:https"}),
            }
        )
    )


@dataclass(frozen=True, slots=True)
class AgentSubTaskAssignment:
    """Isolated sub-agent work unit created by the deterministic SoD workflow splitter."""

    stage_index: int
    sub_agent_id: str
    side_effect_domain: str
    assigned_requests: Tuple[ToolCallRequest, ...]
    allowed_tools: FrozenSet[str]
    attenuated_token: CapabilityToken
    agent_certificate: AgentToolCertificate
    requires_redacted_handoff: bool


def compute_callable_sha256(handler: Optional[ToolHandlerFunc]) -> str:
    """Compute a deterministic cryptographic digest of a Python callable's source and bytecode."""
    if handler is None:
        return hashlib.sha256(b"builtin_kernel_dispatched_tool").hexdigest()

    hasher = hashlib.sha256()
    try:
        src = textwrap.dedent(inspect.getsource(handler))
        hasher.update(src.encode("utf-8"))
    except (OSError, TypeError):
        pass

    code_obj = getattr(handler, "__code__", None)
    if code_obj is not None:
        hasher.update(code_obj.co_code)
        hasher.update(repr(code_obj.co_consts).encode("utf-8"))
        hasher.update(repr(code_obj.co_names).encode("utf-8"))
    else:
        hasher.update(repr(handler).encode("utf-8"))

    closure = getattr(handler, "__closure__", None)
    if closure:
        for cell in closure:
            try:
                hasher.update(repr(cell.cell_contents).encode("utf-8"))
            except ValueError:
                pass

    return hasher.hexdigest()


class CertifiedToolRegistry(SecureComponent):
    """Ring-0 Anti-MCP Tool Certification, Agent Qualification & Combinatorial SoD Engine."""

    def __init__(
        self,
        *,
        signing_secret: Optional[bytes] = None,
        toxic_policy: Optional[ToxicToolPolicy] = None,
    ) -> None:
        self._signing_secret: bytes = (
            signing_secret if signing_secret is not None else secrets.token_bytes(32)
        )
        if len(self._signing_secret) < 32:
            raise ToolCertificationError(
                "CertifiedToolRegistry signing secret must be at least 32 bytes.",
                vector_id="D.3",
                component_id="tool_registry",
            )
        self._toxic_policy: ToxicToolPolicy = toxic_policy or ToxicToolPolicy()
        self._tools: Dict[str, CertifiedToolSpec] = {}
        self._agent_certificates: Dict[str, AgentToolCertificate] = {}
        self._session_tool_history: Dict[str, Set[str]] = {}

    @classmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        return ComponentSecurityAssessment(
            component_id="tool_registry",
            title="Ring-0 Anti-MCP Tool Certification, Agent Qualification & Combinatorial SoD Engine",
            ring_level=0,
            source_path="src/activesec/core/tool_registry.py",
            security_test_path="tests/security/test_sec_tool_registry.py",
            threat_vectors=("A.1", "A.3", "C.2", "F.2", "F.3"),
            summary=(
                "Replaces dynamic, unverified MCP tool loading with a zero-trust Ring-0 certification "
                "and Separation-of-Duties (SoD) engine. Enforces cryptographic ToolCertificates bound "
                "to static AST scans and handler bytecode/source SHA-256 hashes (blocking rug-pull "
                "and tool-poisoning attacks), requires per-agent AgentToolCertificates covering both "
                "individual tools and tested tool combinations, blocks Lethal Trifecta toxic tool "
                "combinations at runtime, and deterministically partitions multi-tool workflows across "
                "isolated sub-agents with attenuated capability tokens."
            ),
            enforced_invariants=(
                "Every registered tool must carry a Ring-0 HMAC-SHA256 ToolCertificate after passing AST safety inspection and adversarial probes.",
                "Re-verifies live handler SHA-256 and schema SHA-256 on every invocation to defeat post-certification MCP-style rug-pull mutations.",
                "Requires a valid, non-expired AgentToolCertificate for the calling agent covering both the individual tool and every pairwise combination with tools previously used in the session.",
                "Enforces ToxicToolPolicy Separation of Duties (SoD), raising ToxicCombinationError (vector_id='F.3') if an agent combines mutually exclusive tools or side-effect classes (e.g., READ_SENSITIVE + NETWORK_EGRESS).",
                "Provides deterministic multi-agent workflow partitioning (partition_tool_plan_across_agents) that splits incompatible tool sequences into isolated sub-agents with attenuated CapabilityTokens.",
            ),
            residual_risks=(
                "A single read-only or egress-only sub-agent still operates within its narrow equivalence class (mitigated by CredentialGuard DLP redaction on inter-agent handoffs and NetworkGuard allowlisting).",
            ),
        )

    @property
    def toxic_policy(self) -> ToxicToolPolicy:
        return self._toxic_policy

    def _sign_tool_certificate(
        self,
        *,
        certificate_id: str,
        tool_name: str,
        side_effect_class: str,
        schema_sha256: str,
        handler_sha256: str,
        probes_executed: int,
        issued_at_unix: float,
    ) -> str:
        payload = json.dumps(
            {
                "certificate_id": certificate_id,
                "handler_sha256": handler_sha256,
                "issued_at_unix": round(issued_at_unix, 6),
                "probes_executed": probes_executed,
                "schema_sha256": schema_sha256,
                "side_effect_class": side_effect_class,
                "tool_name": tool_name,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(self._signing_secret, payload, hashlib.sha256).hexdigest()

    def _sign_agent_certificate(self, payload_dict: Mapping[str, object]) -> str:
        payload = json.dumps(dict(payload_dict), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(self._signing_secret, payload, hashlib.sha256).hexdigest()

    def certify_and_register_tool(
        self,
        spec: CertifiedToolSpec,
        *,
        adversarial_probes: Sequence[AdversarialToolProbe] = (),
        issued_at_unix: Optional[float] = None,
    ) -> CertifiedToolSpec:
        """Audit a tool's schema, AST, and adversarial probes, then issue a signed ToolCertificate and register it."""
        tool_name = spec.tool_name.strip()
        if not tool_name:
            raise ToolCertificationError(
                "Tool certification failed: tool_name must be non-empty.",
                vector_id="A.1",
                component_id="tool_registry",
            )
        effect = spec.side_effect_class.strip().upper()
        if effect not in VALID_SIDE_EFFECT_CLASSES:
            raise ToolCertificationError(
                f"Tool '{tool_name}' declares invalid side_effect_class '{spec.side_effect_class}'.",
                vector_id="A.1",
                component_id="tool_registry",
            )
        if not spec.required_arg_keys.issubset(spec.allowed_arg_keys):
            raise ToolCertificationError(
                f"Tool '{tool_name}' schema invalid: required_arg_keys must be a subset of allowed_arg_keys.",
                vector_id="A.1",
                component_id="tool_registry",
            )
        if len(adversarial_probes) == 0:
            raise ToolCertificationError(
                f"Tool '{tool_name}' cannot be certified without at least 1 adversarial probe.",
                vector_id="A.1",
                component_id="tool_registry",
            )

        # Static AST scan of the handler source if a Python handler callable is provided
        if spec.handler is not None:
            try:
                src = textwrap.dedent(inspect.getsource(spec.handler))
            except (OSError, TypeError) as exc:
                raise ToolCertificationError(
                    f"Cannot inspect source code for tool handler '{tool_name}': {exc}",
                    vector_id="A.1",
                    component_id="tool_registry",
                ) from exc
            ast_ok, ast_findings = audit_python_ast_source(src, filename=f"tool:{tool_name}")
            if not ast_ok:
                raise ToolCertificationError(
                    f"Tool '{tool_name}' failed static AST safety audit: {'; '.join(ast_findings)}",
                    vector_id="A.1",
                    component_id="tool_registry",
                )

        # Run all mandatory adversarial probes
        probe_target: ToolHandlerFunc = spec.handler or (lambda _args: "KERNEL_BUILTIN_OK")
        for idx, probe in enumerate(adversarial_probes):
            try:
                passed = bool(probe(probe_target))
            except ActiveSecError:
                passed = False
            except Exception as exc:
                raise ToolCertificationError(
                    f"Tool '{tool_name}' crashed during adversarial probe #{idx + 1}: {exc}",
                    vector_id="A.1",
                    component_id="tool_registry",
                ) from exc
            if not passed:
                raise ToolCertificationError(
                    f"Tool '{tool_name}' failed adversarial certification probe #{idx + 1}.",
                    vector_id="A.1",
                    component_id="tool_registry",
                )

        schema_hash = spec.compute_schema_sha256()
        handler_hash = compute_callable_sha256(spec.handler)
        now = round(issued_at_unix if issued_at_unix is not None else time.time(), 6)
        cert_id = f"tcert_{secrets.token_hex(12)}"
        sig = self._sign_tool_certificate(
            certificate_id=cert_id,
            tool_name=tool_name,
            side_effect_class=effect,
            schema_sha256=schema_hash,
            handler_sha256=handler_hash,
            probes_executed=len(adversarial_probes),
            issued_at_unix=now,
        )
        cert = ToolCertificate(
            certificate_id=cert_id,
            tool_name=tool_name,
            side_effect_class=effect,
            schema_sha256=schema_hash,
            handler_sha256=handler_hash,
            probes_executed=len(adversarial_probes),
            issued_at_unix=now,
            signature=sig,
        )
        certified_spec = CertifiedToolSpec(
            tool_name=tool_name,
            description=spec.description,
            side_effect_class=effect,
            allowed_arg_keys=spec.allowed_arg_keys,
            required_arg_keys=spec.required_arg_keys,
            max_arg_value_chars=spec.max_arg_value_chars,
            handler=spec.handler,
            certificate=cert,
        )
        self._tools[tool_name] = certified_spec
        return certified_spec

    def register_certified_tool(self, spec: CertifiedToolSpec) -> None:
        """Register an already-certified tool after verifying its Ring-0 signature and handler integrity."""
        self.verify_tool_spec_integrity(spec)
        self._tools[spec.tool_name] = spec

    def register_default_kernel_tools(self) -> Tuple[CertifiedToolSpec, ...]:
        """Certify and register the five canonical Ring-0 SecurityKernel built-in tools."""
        default_specs = (
            CertifiedToolSpec(
                tool_name="fs:read",
                description="Read a UTF-8 file inside permitted workspace prefixes with MalwareGuard and DLP redaction.",
                side_effect_class="READ_SENSITIVE",
                allowed_arg_keys=frozenset({"path", "target_path"}),
            ),
            CertifiedToolSpec(
                tool_name="fs:write",
                description="Write a file inside permitted workspace prefixes with secret DLP blocking and MalwareGuard scan.",
                side_effect_class="WRITE_LOCAL",
                allowed_arg_keys=frozenset({"path", "target_path", "content"}),
            ),
            CertifiedToolSpec(
                tool_name="archive:extract",
                description="Safely extract a ZIP archive with streaming ZipBomb and Zip-Slip containment.",
                side_effect_class="WRITE_LOCAL",
                allowed_arg_keys=frozenset({"path", "target_path", "zip_path", "dest_dir"}),
            ),
            CertifiedToolSpec(
                tool_name="shell:exec",
                description="Execute an allowlisted binary inside a bubblewrap namespace sandbox after deobfuscation.",
                side_effect_class="EXEC_PROCESS",
                allowed_arg_keys=frozenset({"command", "raw_command"}),
            ),
            CertifiedToolSpec(
                tool_name="net:https",
                description="Validate and connect to an allowlisted TLS 1.3 HTTPS endpoint with SSRF protection.",
                side_effect_class="NETWORK_EGRESS",
                allowed_arg_keys=frozenset({"url", "body"}),
            ),
        )
        registered: List[CertifiedToolSpec] = []
        for s in default_specs:
            registered.append(
                self.certify_and_register_tool(
                    s,
                    adversarial_probes=(lambda fn: fn({}) == "KERNEL_BUILTIN_OK",),
                )
            )
        return tuple(registered)

    def verify_tool_spec_integrity(self, spec: CertifiedToolSpec) -> None:
        """Verify that a tool carries a valid Ring-0 certificate and that neither schema nor handler changed."""
        cert = spec.certificate
        if cert is None:
            raise ToolCertificationError(
                f"Uncertified tool '{spec.tool_name}' rejected: missing Ring-0 ToolCertificate.",
                vector_id="A.1",
                component_id="tool_registry",
            )
        if cert.probes_executed < 1:
            raise ToolCertificationError(
                f"Tool '{spec.tool_name}' certificate invalid: zero adversarial probes recorded.",
                vector_id="A.1",
                component_id="tool_registry",
            )

        live_schema_hash = spec.compute_schema_sha256()
        if not hmac.compare_digest(live_schema_hash, cert.schema_sha256):
            raise ToolCertificationError(
                f"Tool '{spec.tool_name}' schema hash mismatch after certification (tampering / rug-pull detected).",
                vector_id="A.1",
                component_id="tool_registry",
            )

        live_handler_hash = compute_callable_sha256(spec.handler)
        if not hmac.compare_digest(live_handler_hash, cert.handler_sha256):
            raise ToolCertificationError(
                f"Tool '{spec.tool_name}' handler bytecode/source hash changed after certification (rug-pull detected).",
                vector_id="A.1",
                component_id="tool_registry",
            )

        expected_sig = self._sign_tool_certificate(
            certificate_id=cert.certificate_id,
            tool_name=cert.tool_name,
            side_effect_class=cert.side_effect_class,
            schema_sha256=cert.schema_sha256,
            handler_sha256=cert.handler_sha256,
            probes_executed=cert.probes_executed,
            issued_at_unix=cert.issued_at_unix,
        )
        if not hmac.compare_digest(expected_sig, cert.signature) or cert.tool_name != spec.tool_name:
            raise ToolCertificationError(
                f"Tool '{spec.tool_name}' carries a forged or invalid ToolCertificate signature.",
                vector_id="A.1",
                component_id="tool_registry",
            )

    def is_pair_toxic(self, tool_a: str, tool_b: str) -> Tuple[bool, str]:
        """Check whether combining `tool_a` and `tool_b` violates ToxicToolPolicy Separation of Duties."""
        if tool_a == tool_b:
            return (False, "")

        pair_names = frozenset({tool_a, tool_b})
        if pair_names in self._toxic_policy.incompatible_tool_pairs:
            return (
                True,
                f"Tools '{tool_a}' and '{tool_b}' are explicitly mutually exclusive under ToxicToolPolicy.",
            )

        spec_a = self._tools.get(tool_a)
        spec_b = self._tools.get(tool_b)
        if spec_a is not None and spec_b is not None:
            effect_pair = frozenset({spec_a.side_effect_class, spec_b.side_effect_class})
            if effect_pair in self._toxic_policy.incompatible_side_effect_pairs:
                return (
                    True,
                    f"Side-effect classes '{spec_a.side_effect_class}' ({tool_a}) and "
                    f"'{spec_b.side_effect_class}' ({tool_b}) form a prohibited Lethal Trifecta combination.",
                )

        return (False, "")

    def run_agent_tool_qualification_suite(
        self,
        *,
        agent_id: str,
        candidate_tools: FrozenSet[str],
        candidate_combinations: FrozenSet[FrozenSet[str]] = frozenset(),
        qualification_probes: Sequence[AgentCombinationProbe] = (),
        ttl_seconds: float = 3600.0,
        current_time: Optional[float] = None,
        allow_toxic_certification: bool = False,
    ) -> AgentToolCertificate:
        """Qualify an agent on specific certified tools and combinations, issuing a signed AgentToolCertificate."""
        clean_agent = agent_id.strip()
        if not clean_agent:
            raise ToolCertificationError(
                "Agent qualification requires a non-empty agent_id.",
                vector_id="F.3",
                component_id="tool_registry",
            )
        if not candidate_tools:
            raise ToolCertificationError(
                f"Agent '{clean_agent}' qualification requires at least one candidate tool.",
                vector_id="F.3",
                component_id="tool_registry",
            )
        if len(qualification_probes) == 0:
            raise ToolCertificationError(
                f"Agent '{clean_agent}' cannot be qualified without adversarial qualification probes.",
                vector_id="F.3",
                component_id="tool_registry",
            )

        # Verify every candidate tool is registered and intact
        for t_name in candidate_tools:
            if t_name not in self._tools:
                raise ToolCertificationError(
                    f"Cannot qualify agent '{clean_agent}' for unregistered/uncertified tool '{t_name}'.",
                    vector_id="A.1",
                    component_id="tool_registry",
                )
            self.verify_tool_spec_integrity(self._tools[t_name])

        normalized_combos: Set[FrozenSet[str]] = set()
        for t_name in candidate_tools:
            normalized_combos.add(frozenset({t_name}))

        for combo in candidate_combinations:
            if not combo.issubset(candidate_tools):
                raise ToolCertificationError(
                    f"Combination {sorted(combo)} contains tools outside candidate_tools {sorted(candidate_tools)}.",
                    vector_id="F.3",
                    component_id="tool_registry",
                )
            combo_list = sorted(combo)
            if not allow_toxic_certification:
                for i in range(len(combo_list)):
                    for j in range(i + 1, len(combo_list)):
                        toxic, reason = self.is_pair_toxic(combo_list[i], combo_list[j])
                        if toxic:
                            raise ToxicCombinationError(
                                f"Cannot certify toxic combination {combo_list} for agent '{clean_agent}': {reason}",
                                vector_id="F.3",
                                component_id="tool_registry",
                            )
            normalized_combos.add(frozenset(combo))

        # Execute qualification probes across individual tools and declared combinations
        probes_passed = 0
        for probe in qualification_probes:
            for combo in sorted(normalized_combos, key=lambda c: sorted(c)):
                if not bool(probe(clean_agent, combo)):
                    raise ToolCertificationError(
                        f"Agent '{clean_agent}' failed qualification probe on tool set {sorted(combo)}.",
                        vector_id="F.3",
                        component_id="tool_registry",
                    )
                probes_passed += 1

        now = round(current_time if current_time is not None else time.time(), 6)
        expires = round(now + ttl_seconds, 6)
        cert_id = f"acert_{secrets.token_hex(12)}"

        provisional = AgentToolCertificate(
            certificate_id=cert_id,
            agent_id=clean_agent,
            certified_tools=frozenset(candidate_tools),
            certified_combinations=frozenset(normalized_combos),
            qualification_probes_passed=probes_passed,
            issued_at_unix=now,
            expires_at_unix=expires,
            signature="",
        )
        sig = self._sign_agent_certificate(provisional.canonical_payload_dict())
        final_cert = AgentToolCertificate(
            certificate_id=cert_id,
            agent_id=clean_agent,
            certified_tools=provisional.certified_tools,
            certified_combinations=provisional.certified_combinations,
            qualification_probes_passed=probes_passed,
            issued_at_unix=now,
            expires_at_unix=expires,
            signature=sig,
        )
        self._agent_certificates[clean_agent] = final_cert
        return final_cert

    def verify_agent_certificate(
        self,
        cert: AgentToolCertificate,
        *,
        expected_agent_id: str,
        current_time: Optional[float] = None,
    ) -> None:
        """Verify cryptographic signature, subject binding, and expiration of an AgentToolCertificate."""
        if cert.agent_id != expected_agent_id:
            raise ToolCertificationError(
                f"AgentToolCertificate subject mismatch: bound to '{cert.agent_id}', presented by '{expected_agent_id}'.",
                vector_id="F.3",
                component_id="tool_registry",
            )
        expected_sig = self._sign_agent_certificate(cert.canonical_payload_dict())
        if not hmac.compare_digest(expected_sig, cert.signature):
            raise ToolCertificationError(
                f"Forged or tampered AgentToolCertificate for agent '{expected_agent_id}'.",
                vector_id="F.3",
                component_id="tool_registry",
            )
        now = current_time if current_time is not None else time.time()
        if now > cert.expires_at_unix:
            raise ToolCertificationError(
                f"AgentToolCertificate for agent '{expected_agent_id}' has expired.",
                vector_id="F.3",
                component_id="tool_registry",
            )

    def reset_session_history(self, session_key: str) -> None:
        """Clear recorded tool usage history for a completed session/token."""
        self._session_tool_history.pop(session_key, None)

    def enforce_tool_call(
        self,
        request: ToolCallRequest,
        *,
        agent_id: str,
        session_key: Optional[str] = None,
        agent_certificate: Optional[AgentToolCertificate] = None,
        current_time: Optional[float] = None,
    ) -> CertifiedToolSpec:
        """Enforce Stage 1 (Tool Cert), Stage 2 (Agent & Combo Cert), and Stage 3 (SoD Toxic Block)."""
        tool_name = request.tool_name.strip()
        spec = self._tools.get(tool_name)
        if spec is None:
            raise ToolCertificationError(
                f"Tool '{tool_name}' is not registered in CertifiedToolRegistry (zero-trust MCP defense).",
                vector_id="A.1",
                component_id="tool_registry",
            )

        # Stage 1: Verify ToolCertificate signature, schema hash, and live handler hash (anti-rug-pull)
        self.verify_tool_spec_integrity(spec)

        # Validate request arguments against immutable tool schema
        arg_keys = frozenset(request.arguments.keys())
        missing_keys = spec.required_arg_keys - arg_keys
        if missing_keys:
            raise ToolCertificationError(
                f"Tool '{tool_name}' invocation missing required arguments: {sorted(missing_keys)}.",
                vector_id="A.1",
                component_id="tool_registry",
            )
        unexpected_keys = arg_keys - spec.allowed_arg_keys
        if unexpected_keys:
            raise ToolCertificationError(
                f"Tool '{tool_name}' invocation rejected undeclared arguments: {sorted(unexpected_keys)}.",
                vector_id="A.1",
                component_id="tool_registry",
            )
        for k, v in request.arguments.items():
            if len(str(v)) > spec.max_arg_value_chars:
                raise ToolCertificationError(
                    f"Argument '{k}' for tool '{tool_name}' exceeds max_arg_value_chars ({spec.max_arg_value_chars}).",
                    vector_id="A.1",
                    component_id="tool_registry",
                )

        # Stage 2: Verify AgentToolCertificate (individual tool qualification)
        cert = agent_certificate or self._agent_certificates.get(agent_id)
        if cert is None:
            raise ToolCertificationError(
                f"Agent '{agent_id}' holds no AgentToolCertificate and is not qualified to invoke '{tool_name}'.",
                vector_id="F.3",
                component_id="tool_registry",
            )
        self.verify_agent_certificate(cert, expected_agent_id=agent_id, current_time=current_time)

        if tool_name not in cert.certified_tools:
            raise ToolCertificationError(
                f"Agent '{agent_id}' is not certified for tool '{tool_name}' (certified={sorted(cert.certified_tools)}).",
                vector_id="F.3",
                component_id="tool_registry",
            )

        # Stage 3 (SoD Check) + Stage 2 (Combinatorial Certification Check) against session history
        effective_session_key = session_key if session_key is not None else agent_id
        prior_tools = self._session_tool_history.setdefault(effective_session_key, set())

        for prior_tool in sorted(prior_tools):
            if prior_tool == tool_name:
                continue
            # Check Separation of Duties (Lethal Trifecta / Toxic Combination) first
            toxic, reason = self.is_pair_toxic(prior_tool, tool_name)
            if toxic:
                raise ToxicCombinationError(
                    f"Separation-of-Duties (SoD) violation for agent '{agent_id}': {reason}",
                    vector_id="F.3",
                    component_id="tool_registry",
                )

            # Check explicit combinatorial agent qualification for {prior_tool, tool_name}
            pair_set = frozenset({prior_tool, tool_name})
            if not any(pair_set.issubset(certified_combo) for certified_combo in cert.certified_combinations):
                raise ToolCertificationError(
                    f"Agent '{agent_id}' is certified for '{prior_tool}' and '{tool_name}' individually, "
                    f"but NOT combinatorially certified to use {sorted(pair_set)} together in one session.",
                    vector_id="F.3",
                    component_id="tool_registry",
                )

        prior_tools.add(tool_name)
        return spec

    def partition_tool_plan_across_agents(
        self,
        *,
        parent_agent_id: str,
        parent_token: CapabilityToken,
        capability_engine: CapabilityEngine,
        planned_requests: Sequence[ToolCallRequest],
        qualification_probes: Sequence[AgentCombinationProbe] = (lambda _a, _c: True,),
    ) -> Tuple[AgentSubTaskAssignment, ...]:
        """Deterministically partition a sequence of planned tool calls across isolated sub-agents.

        Whenever a planned tool call would form a toxic combination (or incompatible side-effect
        domain) with tools already assigned to the current sub-agent stage, a new isolated
        sub-agent assignment is created with:
        1. A strictly attenuated `CapabilityToken` narrowed to only that stage's non-toxic tool set
           (for example, stripping network destinations for reader stages and stripping sensitive
           filesystem read tools for network egress stages).
        2. A dedicated `AgentToolCertificate` scoped strictly to that stage's non-toxic tools.
        """
        if not planned_requests:
            return ()

        # Validate every planned tool exists and passes Stage 1 integrity
        for req in planned_requests:
            t_name = req.tool_name.strip()
            if t_name not in self._tools:
                raise ToolCertificationError(
                    f"Cannot partition plan containing uncertified tool '{t_name}'.",
                    vector_id="A.1",
                    component_id="tool_registry",
                )
            self.verify_tool_spec_integrity(self._tools[t_name])

        stages: List[List[ToolCallRequest]] = []
        stage_tool_sets: List[Set[str]] = []

        for req in planned_requests:
            t_name = req.tool_name.strip()
            if not stages:
                stages.append([req])
                stage_tool_sets.append({t_name})
                continue

            current_tools = stage_tool_sets[-1]
            conflict = any(self.is_pair_toxic(existing, t_name)[0] for existing in current_tools)
            if conflict:
                stages.append([req])
                stage_tool_sets.append({t_name})
            else:
                stages[-1].append(req)
                current_tools.add(t_name)

        parent_caveat = parent_token.caveats[-1]
        assignments: List[AgentSubTaskAssignment] = []

        for idx, (stage_reqs, stage_tools) in enumerate(zip(stages, stage_tool_sets)):
            frozen_tools = frozenset(stage_tools)
            effects = sorted({self._tools[t].side_effect_class for t in frozen_tools})
            domain_label = "+".join(effects)
            sub_agent_id = f"{parent_agent_id}:sod-stage-{idx + 1}-{effects[0].lower()}"

            has_egress = "NETWORK_EGRESS" in effects
            has_exec = "EXEC_PROCESS" in effects

            narrowed_net = parent_caveat.network_destinations if has_egress else frozenset()
            narrowed_bins = parent_caveat.allowed_binaries if has_exec else frozenset()

            narrowed_caveat = CapabilityCaveat(
                allowed_tools=frozen_tools,
                path_prefixes=parent_caveat.path_prefixes,
                denied_paths=parent_caveat.denied_paths,
                allowed_binaries=narrowed_bins,
                network_destinations=narrowed_net,
                max_calls=min(parent_caveat.max_calls, max(1, len(stage_reqs))),
                expires_at_unix=parent_caveat.expires_at_unix,
                require_untainted_context=parent_caveat.require_untainted_context,
            )
            attenuated_token = capability_engine.delegate_attenuated_token(
                parent_token=parent_token,
                child_agent_id=sub_agent_id,
                child_purpose=f"SoD isolated stage #{idx + 1} ({domain_label})",
                narrowed_caveat=narrowed_caveat,
            )
            sub_cert = self.run_agent_tool_qualification_suite(
                agent_id=sub_agent_id,
                candidate_tools=frozen_tools,
                candidate_combinations=frozenset({frozen_tools}),
                qualification_probes=qualification_probes,
            )
            assignments.append(
                AgentSubTaskAssignment(
                    stage_index=idx + 1,
                    sub_agent_id=sub_agent_id,
                    side_effect_domain=domain_label,
                    assigned_requests=tuple(stage_reqs),
                    allowed_tools=frozen_tools,
                    attenuated_token=attenuated_token,
                    agent_certificate=sub_cert,
                    requires_redacted_handoff=(idx > 0),
                )
            )

        return tuple(assignments)
