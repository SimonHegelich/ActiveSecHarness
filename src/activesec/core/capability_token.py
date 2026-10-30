"""Ring-0 cryptographic sudo capability token engine with monotonic attenuation.

Implements chained HMAC-SHA256 capability tokens (Macaroon-inspired), strict subset
attenuation verification across tools, canonical paths, binaries, network targets,
TTL, call quotas, and prompt-injection taint locking.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import FrozenSet, Optional, Tuple

from activesec.core.component import ComponentSecurityAssessment, SecureComponent
from activesec.core.exceptions import CapabilityViolationError


@dataclass(frozen=True, slots=True)
class CapabilityCaveat:
    """Immutable constraint block restricting a capability token's authority."""

    allowed_tools: FrozenSet[str]
    path_prefixes: Tuple[str, ...]
    denied_paths: Tuple[str, ...] = (".git/hooks", ".env", ".ssh", "src/activesec")
    allowed_binaries: FrozenSet[str] = frozenset()
    network_destinations: FrozenSet[str] = frozenset()
    max_calls: int = 10
    expires_at_unix: float = 0.0
    require_untainted_context: bool = True

    def canonical_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-serializable dictionary for cryptographic signing."""
        return {
            "allowed_binaries": sorted(self.allowed_binaries),
            "allowed_tools": sorted(self.allowed_tools),
            "denied_paths": list(self.denied_paths),
            "expires_at_unix": round(self.expires_at_unix, 6),
            "max_calls": self.max_calls,
            "network_destinations": sorted(self.network_destinations),
            "path_prefixes": [os.path.realpath(p) for p in self.path_prefixes],
            "require_untainted_context": self.require_untainted_context,
        }


@dataclass(frozen=True, slots=True)
class CapabilityToken:
    """Cryptographically chained capability token bound to a specific agent and purpose."""

    token_id: str
    parent_token_id: Optional[str]
    issuer_ring: int
    subject_agent_id: str
    task_purpose: str
    caveats: Tuple[CapabilityCaveat, ...]
    signature: str


class CapabilityEngine(SecureComponent):
    """Ring-0 engine for issuing, attenuating, revoking, and verifying capability tokens."""

    def __init__(self, master_secret: Optional[bytes] = None) -> None:
        self._master_secret: bytes = master_secret if master_secret is not None else secrets.token_bytes(32)
        if len(self._master_secret) < 32:
            raise CapabilityViolationError(
                "Master signing secret must be at least 32 bytes of high-entropy randomness.",
                vector_id="D.3",
                component_id="capability_token",
            )
        self._call_counts: dict[str, int] = {}
        self._revoked_tokens: set[str] = set()

    @classmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        return ComponentSecurityAssessment(
            component_id="capability_token",
            title="Ring-0 Sudo Capability Token & Attenuation Engine",
            ring_level=0,
            source_path="src/activesec/core/capability_token.py",
            security_test_path="tests/security/test_sec_capability_token.py",
            threat_vectors=("A.1", "A.3", "F.2", "F.3"),
            summary=(
                "Enforces cryptographic sudo capability chains with Macaroon-style chained HMAC-SHA256 "
                "signatures, monotonic attenuation on sub-agent delegation, canonical path confinement, "
                "call-quota tracking, and automatic privilege locking upon prompt-injection context taint."
            ),
            enforced_invariants=(
                "All tokens are signed with a >=256-bit Ring-0 secret using constant-time hmac.compare_digest.",
                "Delegation strictly narrows authority: Child tools, binaries, network targets, paths, TTL, and quotas must be a mathematical subset of the parent token.",
                "Canonical path resolution (os.path.realpath) prevents ../ traversal and protects Ring-0 harness source and dotfiles.",
                "Tainted agents (context_tainted=True) are deterministically blocked when require_untainted_context is active.",
            ),
            residual_risks=(
                "In-process memory disclosure if untrusted native C extensions run inside the Ring-0 Python interpreter process (mitigated by running tools in isolated bwrap subprocesses).",
            ),
        )

    def _compute_chain_signature(
        self,
        *,
        token_id: str,
        parent_token_id: Optional[str],
        issuer_ring: int,
        subject_agent_id: str,
        task_purpose: str,
        caveats: Tuple[CapabilityCaveat, ...],
    ) -> str:
        header_payload = json.dumps(
            {
                "issuer_ring": issuer_ring,
                "parent_token_id": parent_token_id,
                "subject_agent_id": subject_agent_id,
                "task_purpose": task_purpose,
                "token_id": token_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        chained_mac = hmac.new(self._master_secret, header_payload, hashlib.sha256).digest()
        for caveat in caveats:
            caveat_bytes = json.dumps(
                caveat.canonical_dict(),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            chained_mac = hmac.new(chained_mac, caveat_bytes, hashlib.sha256).digest()

        return chained_mac.hex()

    def issue_root_token(
        self,
        *,
        subject_agent_id: str,
        task_purpose: str,
        caveat: CapabilityCaveat,
    ) -> CapabilityToken:
        """Issue a Ring-1 root capability token authorized by the human operator."""
        if not subject_agent_id.strip() or not task_purpose.strip():
            raise CapabilityViolationError(
                "Root token requires non-empty subject_agent_id and task_purpose.",
                vector_id="A.1",
                component_id="capability_token",
            )
        token_id = secrets.token_hex(16)
        caveats = (caveat,)
        signature = self._compute_chain_signature(
            token_id=token_id,
            parent_token_id=None,
            issuer_ring=1,
            subject_agent_id=subject_agent_id,
            task_purpose=task_purpose,
            caveats=caveats,
        )
        self._call_counts[token_id] = 0
        return CapabilityToken(
            token_id=token_id,
            parent_token_id=None,
            issuer_ring=1,
            subject_agent_id=subject_agent_id,
            task_purpose=task_purpose,
            caveats=caveats,
            signature=signature,
        )

    def delegate_attenuated_token(
        self,
        *,
        parent_token: CapabilityToken,
        child_agent_id: str,
        child_purpose: str,
        narrowed_caveat: CapabilityCaveat,
    ) -> CapabilityToken:
        """Delegate an attenuated sub-token to a child agent, enforcing strict scope narrowing."""
        self._verify_signature_and_revocation(parent_token)
        effective_parent = parent_token.caveats[-1]

        # 1. Verify monotonic tool subset
        if not narrowed_caveat.allowed_tools.issubset(effective_parent.allowed_tools):
            raise CapabilityViolationError(
                "Attenuation violation: child token requests tools not present in parent token.",
                vector_id="F.3",
                component_id="capability_token",
            )

        # 2. Verify monotonic binary subset
        if not narrowed_caveat.allowed_binaries.issubset(effective_parent.allowed_binaries):
            raise CapabilityViolationError(
                "Attenuation violation: child token requests binaries not allowed by parent token.",
                vector_id="A.1",
                component_id="capability_token",
            )

        # 3. Verify monotonic network subset
        if not narrowed_caveat.network_destinations.issubset(effective_parent.network_destinations):
            raise CapabilityViolationError(
                "Attenuation violation: child token expands network destinations beyond parent token.",
                vector_id="C.2",
                component_id="capability_token",
            )

        # 4. Verify canonical path prefix containment
        parent_real_prefixes = [os.path.realpath(p) for p in effective_parent.path_prefixes]
        for child_path in narrowed_caveat.path_prefixes:
            real_child = os.path.realpath(child_path)
            if not any(
                real_child == pp or real_child.startswith(pp + os.sep)
                for pp in parent_real_prefixes
            ):
                raise CapabilityViolationError(
                    f"Attenuation violation: child path '{child_path}' is outside parent prefixes.",
                    vector_id="F.3",
                    component_id="capability_token",
                )

        # 5. Verify denied paths are preserved or expanded
        if not set(effective_parent.denied_paths).issubset(set(narrowed_caveat.denied_paths)):
            raise CapabilityViolationError(
                "Attenuation violation: child token attempts to remove parent denied_paths.",
                vector_id="A.3",
                component_id="capability_token",
            )

        # 6. Verify TTL and call quota narrowing
        if narrowed_caveat.expires_at_unix > effective_parent.expires_at_unix:
            raise CapabilityViolationError(
                "Attenuation violation: child token TTL exceeds parent token expiration.",
                vector_id="F.3",
                component_id="capability_token",
            )
        if narrowed_caveat.max_calls > effective_parent.max_calls:
            raise CapabilityViolationError(
                "Attenuation violation: child token max_calls exceeds parent quota.",
                vector_id="F.3",
                component_id="capability_token",
            )
        if effective_parent.require_untainted_context and not narrowed_caveat.require_untainted_context:
            raise CapabilityViolationError(
                "Attenuation violation: child token cannot disable require_untainted_context.",
                vector_id="F.2",
                component_id="capability_token",
            )

        child_id = secrets.token_hex(16)
        combined_caveats = parent_token.caveats + (narrowed_caveat,)
        signature = self._compute_chain_signature(
            token_id=child_id,
            parent_token_id=parent_token.token_id,
            issuer_ring=min(3, parent_token.issuer_ring + 1),
            subject_agent_id=child_agent_id,
            task_purpose=child_purpose,
            caveats=combined_caveats,
        )
        self._call_counts[child_id] = 0
        return CapabilityToken(
            token_id=child_id,
            parent_token_id=parent_token.token_id,
            issuer_ring=min(3, parent_token.issuer_ring + 1),
            subject_agent_id=child_agent_id,
            task_purpose=child_purpose,
            caveats=combined_caveats,
            signature=signature,
        )

    def revoke_token(self, token_id: str) -> None:
        """Immediately revoke a token ID (and any chain referencing it as parent)."""
        self._revoked_tokens.add(token_id)

    def _verify_signature_and_revocation(self, token: CapabilityToken) -> None:
        if not token.caveats:
            raise CapabilityViolationError(
                "Token contains no caveats.",
                vector_id="A.1",
                component_id="capability_token",
            )
        if token.token_id in self._revoked_tokens or (
            token.parent_token_id is not None and token.parent_token_id in self._revoked_tokens
        ):
            raise CapabilityViolationError(
                f"Token '{token.token_id}' or its parent has been revoked.",
                vector_id="A.1",
                component_id="capability_token",
            )
        expected_sig = self._compute_chain_signature(
            token_id=token.token_id,
            parent_token_id=token.parent_token_id,
            issuer_ring=token.issuer_ring,
            subject_agent_id=token.subject_agent_id,
            task_purpose=token.task_purpose,
            caveats=token.caveats,
        )
        if not hmac.compare_digest(expected_sig, token.signature):
            raise CapabilityViolationError(
                "Cryptographic signature verification failed (forged or tampered token).",
                vector_id="A.3",
                component_id="capability_token",
            )

    def verify_tool_call(
        self,
        *,
        token: CapabilityToken,
        agent_id: str,
        tool_name: str,
        target_path: Optional[str] = None,
        binary_name: Optional[str] = None,
        network_destination: Optional[str] = None,
        context_tainted: bool = False,
        current_time: Optional[float] = None,
    ) -> None:
        """Verify every caveat in the token chain for a concrete tool invocation."""
        self._verify_signature_and_revocation(token)

        if token.subject_agent_id != agent_id:
            raise CapabilityViolationError(
                f"Token subject mismatch: bound to '{token.subject_agent_id}', used by '{agent_id}'.",
                vector_id="F.3",
                component_id="capability_token",
            )

        now = current_time if current_time is not None else time.time()
        used_calls = self._call_counts.get(token.token_id, 0)

        for caveat in token.caveats:
            if now > caveat.expires_at_unix:
                raise CapabilityViolationError(
                    "Capability token has expired (TTL exceeded).",
                    vector_id="A.1",
                    component_id="capability_token",
                )
            if used_calls >= caveat.max_calls:
                raise CapabilityViolationError(
                    f"Capability call quota exhausted ({used_calls}/{caveat.max_calls}).",
                    vector_id="A.1",
                    component_id="capability_token",
                )
            if context_tainted and caveat.require_untainted_context:
                raise CapabilityViolationError(
                    "Agent context is TAINTED by untrusted input; privileged tool call blocked.",
                    vector_id="F.2",
                    component_id="capability_token",
                )
            if tool_name not in caveat.allowed_tools:
                raise CapabilityViolationError(
                    f"Tool '{tool_name}' is not permitted by capability token.",
                    vector_id="A.1",
                    component_id="capability_token",
                )
            if binary_name is not None and binary_name not in caveat.allowed_binaries:
                raise CapabilityViolationError(
                    f"Binary '{binary_name}' is not permitted by capability token (LotL defense).",
                    vector_id="A.1",
                    component_id="capability_token",
                )
            if network_destination is not None and network_destination not in caveat.network_destinations:
                raise CapabilityViolationError(
                    f"Network destination '{network_destination}' is not permitted by capability token.",
                    vector_id="C.2",
                    component_id="capability_token",
                )
            if target_path is not None:
                real_target = os.path.realpath(target_path)
                real_prefixes = [os.path.realpath(p) for p in caveat.path_prefixes]
                if not any(
                    real_target == prefix or real_target.startswith(prefix + os.sep)
                    for prefix in real_prefixes
                ):
                    raise CapabilityViolationError(
                        f"Target path '{target_path}' is outside permitted capability prefixes.",
                        vector_id="A.3",
                        component_id="capability_token",
                    )
                for denied in caveat.denied_paths:
                    normalized_denied = denied.strip("/")
                    if (
                        real_target.endswith(os.sep + normalized_denied)
                        or (os.sep + normalized_denied + os.sep) in (real_target + os.sep)
                    ):
                        raise CapabilityViolationError(
                            f"Target path '{target_path}' matches protected denied path '{denied}'.",
                            vector_id="A.4",
                            component_id="capability_token",
                        )

        self._call_counts[token.token_id] = used_calls + 1
