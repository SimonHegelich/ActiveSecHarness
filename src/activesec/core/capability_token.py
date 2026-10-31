"""Ring-0 cryptographic sudo capability token engine with monotonic attenuation.

Implements chained HMAC-SHA256 capability tokens (Macaroon-inspired), strict subset
attenuation verification across tools, canonical paths, binaries, network targets,
TTL, call quotas, and prompt-injection taint locking.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import json
import os
import secrets
import shlex
import time
from dataclasses import dataclass
from typing import FrozenSet, Mapping, Optional, Sequence, Set, Tuple

from activesec.core.component import ComponentSecurityAssessment, SecureComponent
from activesec.core.exceptions import CapabilityViolationError


class TrustLevel(str, enum.Enum):
    """4-Element Provenance Trust Lattice L_trust = {TRUSTED <= SANITIZED <= DERIVED <= UNTRUSTED}."""

    TRUSTED = "TRUSTED"
    SANITIZED = "SANITIZED"
    DERIVED = "DERIVED"
    UNTRUSTED = "UNTRUSTED"

    @property
    def rank(self) -> int:
        return _TRUST_RANKS[self]

    def join(self, other: "TrustLevel") -> "TrustLevel":
        """Least upper bound (sqcup) in L_trust."""
        return self if self.rank >= other.rank else other


_TRUST_RANKS: Mapping[TrustLevel, int] = {
    TrustLevel.TRUSTED: 0,
    TrustLevel.SANITIZED: 1,
    TrustLevel.DERIVED: 2,
    TrustLevel.UNTRUSTED: 3,
}


class SensitivityLevel(str, enum.Enum):
    """2-Element Confidentiality Lattice L_sens = {PUBLIC <= SENSITIVE}."""

    PUBLIC = "PUBLIC"
    SENSITIVE = "SENSITIVE"

    @property
    def rank(self) -> int:
        return 1 if self == SensitivityLevel.SENSITIVE else 0

    def join(self, other: "SensitivityLevel") -> "SensitivityLevel":
        """Least upper bound (vee) in L_sens."""
        if self == SensitivityLevel.SENSITIVE or other == SensitivityLevel.SENSITIVE:
            return SensitivityLevel.SENSITIVE
        return SensitivityLevel.PUBLIC


class InformationClass(str, enum.Enum):
    """5-Level Information-Flow Taint & Sensitivity Lattice (compatible projection of L_trust x L_sens).

    Integrity/Taint ordering:
        TRUSTED (0) <= SANITIZED (1) <= DERIVED (2) <= UNTRUSTED (3)
    Sensitivity orthogonal/top absorption:
        SENSITIVE (4) absorbs sensitivity when joined with any flow, or
        blocks unredacted network egress and arbitrary shell execution unless
        explicitly declassified to SANITIZED.
    """

    TRUSTED = "TRUSTED"
    SANITIZED = "SANITIZED"
    DERIVED = "DERIVED"
    UNTRUSTED = "UNTRUSTED"
    SENSITIVE = "SENSITIVE"

    @property
    def lattice_rank(self) -> int:
        return _LATTICE_RANKS[self]

    def join(self, other: "InformationClass") -> "InformationClass":
        """Compute the least upper bound (join \\sqcup) in the 5-level lattice."""
        if self == InformationClass.SENSITIVE or other == InformationClass.SENSITIVE:
            return InformationClass.SENSITIVE
        return self if self.lattice_rank >= other.lattice_rank else other

    def to_composite_label(self) -> "CompositeLabel":
        """Convert a 1D InformationClass into the 2D Product Lattice L_trust x L_sens."""
        if self == InformationClass.SENSITIVE:
            return CompositeLabel(trust=TrustLevel.TRUSTED, sensitivity=SensitivityLevel.SENSITIVE)
        return CompositeLabel(trust=TrustLevel(self.value), sensitivity=SensitivityLevel.PUBLIC)


_LATTICE_RANKS: Mapping[InformationClass, int] = {
    InformationClass.TRUSTED: 0,
    InformationClass.SANITIZED: 1,
    InformationClass.DERIVED: 2,
    InformationClass.UNTRUSTED: 3,
    InformationClass.SENSITIVE: 4,
}


@dataclass(frozen=True, slots=True)
class CompositeLabel:
    """2D Product Information-Flow Label ell = (tau, sigma) in L = L_trust x L_sens (Definition 3.3)."""

    trust: TrustLevel = TrustLevel.TRUSTED
    sensitivity: SensitivityLevel = SensitivityLevel.PUBLIC

    def join(self, other: "CompositeLabel") -> "CompositeLabel":
        """Componentwise join: (tau_1, sigma_1) sqcup (tau_2, sigma_2) = (tau_1 sqcup tau_2, sigma_1 vee sigma_2)."""
        return CompositeLabel(
            trust=self.trust.join(other.trust),
            sensitivity=self.sensitivity.join(other.sensitivity),
        )

    def sanitize(self) -> "CompositeLabel":
        """Structural representation cleaning (e.g. stripping Trojan Unicode / deobfuscating).

        Maps (tau, sigma) |-> (SANITIZED, sigma) while leaving sigma unchanged (Proposition A.2).
        """
        new_trust = TrustLevel.SANITIZED if self.trust != TrustLevel.TRUSTED else TrustLevel.TRUSTED
        return CompositeLabel(trust=new_trust, sensitivity=self.sensitivity)

    def redact_or_declassify(self) -> "CompositeLabel":
        """Authorized DLP secret redaction or Ring-1 declassification waiver.

        Clears sigma |-> PUBLIC while preserving or sanitizing tau (Proposition A.2).
        """
        new_trust = TrustLevel.SANITIZED if self.trust == TrustLevel.UNTRUSTED else self.trust
        return CompositeLabel(trust=new_trust, sensitivity=SensitivityLevel.PUBLIC)

    @property
    def to_information_class(self) -> InformationClass:
        """Project (tau, sigma) onto the 5-level InformationClass enum."""
        if self.sensitivity == SensitivityLevel.SENSITIVE:
            return InformationClass.SENSITIVE
        return InformationClass(self.trust.value)

    @property
    def allowed_actions(self) -> FrozenSet["ActionClass"]:
        """Return the set of ActionClasses permitted under (tau, sigma) in the product lattice."""
        trust_allowed = ALLOWED_ACTIONS_BY_TRUST[self.trust]
        if self.sensitivity == SensitivityLevel.SENSITIVE:
            return trust_allowed & ALLOWED_ACTIONS_FOR_SENSITIVE
        return trust_allowed


class ActionClass(str, enum.Enum):
    """Fine-grained mediation action classes governed by the 5-level taint lattice."""

    FS_READ_WORKSPACE = "FS_READ_WORKSPACE"
    FS_WRITE_WORKSPACE = "FS_WRITE_WORKSPACE"
    ARCHIVE_EXTRACT = "ARCHIVE_EXTRACT"
    SHELL_TEST_ISOLATED = "SHELL_TEST_ISOLATED"
    SHELL_ARBITRARY = "SHELL_ARBITRARY"
    NETWORK_EGRESS = "NETWORK_EGRESS"


# Explicit action-class permissions per InformationClass level:
# - TRUSTED / SANITIZED: All workspace, test, shell, and allowlisted network actions permitted.
# - DERIVED (e.g., internal plan/summary derived after reading an untrusted GitHub issue):
#   Permits workspace fs:read, fs:write, archive:extract, and isolated test runs
#   (pytest / python -m unittest inside SandboxGuard with network disabled), while
#   blocking arbitrary shell execution (SHELL_ARBITRARY) and network egress (NETWORK_EGRESS).
# - UNTRUSTED: Permits only local read/inspection (FS_READ_WORKSPACE); blocks workspace writes,
#   all shell execution, and network egress.
# - SENSITIVE: Permits only local read/write inside workspace; blocks all shell execution
#   and network egress unless explicitly declassified to SANITIZED.
ALLOWED_ACTIONS_BY_TRUST: Mapping[TrustLevel, FrozenSet[ActionClass]] = {
    TrustLevel.TRUSTED: frozenset(ActionClass),
    TrustLevel.SANITIZED: frozenset(ActionClass),
    TrustLevel.DERIVED: frozenset(
        {
            ActionClass.FS_READ_WORKSPACE,
            ActionClass.FS_WRITE_WORKSPACE,
            ActionClass.ARCHIVE_EXTRACT,
            ActionClass.SHELL_TEST_ISOLATED,
        }
    ),
    TrustLevel.UNTRUSTED: frozenset(
        {
            ActionClass.FS_READ_WORKSPACE,
        }
    ),
}

ALLOWED_ACTIONS_FOR_SENSITIVE: FrozenSet[ActionClass] = frozenset(
    {
        ActionClass.FS_READ_WORKSPACE,
        ActionClass.FS_WRITE_WORKSPACE,
    }
)

ALLOWED_ACTIONS_BY_INFO_CLASS: Mapping[InformationClass, FrozenSet[ActionClass]] = {
    InformationClass.TRUSTED: frozenset(ActionClass),
    InformationClass.SANITIZED: frozenset(ActionClass),
    InformationClass.DERIVED: ALLOWED_ACTIONS_BY_TRUST[TrustLevel.DERIVED],
    InformationClass.UNTRUSTED: ALLOWED_ACTIONS_BY_TRUST[TrustLevel.UNTRUSTED],
    InformationClass.SENSITIVE: ALLOWED_ACTIONS_FOR_SENSITIVE,
}

ISOLATED_TEST_BINARIES: FrozenSet[str] = frozenset({"pytest", "python", "python3"})


def classify_tool_action(
    tool_name: str,
    *,
    binary_name: Optional[str] = None,
    raw_command: Optional[str] = None,
) -> ActionClass:
    """Classify a tool call into a fine-grained ActionClass for IFC taint enforcement."""
    if tool_name == "fs:read":
        return ActionClass.FS_READ_WORKSPACE
    if tool_name == "fs:write":
        return ActionClass.FS_WRITE_WORKSPACE
    if tool_name == "archive:extract":
        return ActionClass.ARCHIVE_EXTRACT
    if tool_name == "net:https":
        return ActionClass.NETWORK_EGRESS
    if tool_name == "shell:exec":
        if is_isolated_test_command(binary_name=binary_name, raw_command=raw_command):
            return ActionClass.SHELL_TEST_ISOLATED
        return ActionClass.SHELL_ARBITRARY
    return ActionClass.SHELL_ARBITRARY


def is_isolated_test_command(
    *,
    binary_name: Optional[str] = None,
    raw_command: Optional[str] = None,
) -> bool:
    """Return True if a shell command is strictly an isolated unit-test invocation (pytest / unittest)."""
    if not raw_command:
        return binary_name == "pytest"
    # Reject shell metacharacters, pipes, chaining, or command substitution
    if any(sep in raw_command for sep in (";", "|", "&", "`", "$(", ">", "<", "\n")):
        return False
    try:
        argv = shlex.split(raw_command)
    except ValueError:
        return False
    if not argv:
        return False
    exe = os.path.basename(argv[0])
    if binary_name and os.path.basename(binary_name) != exe:
        return False

    # Case 1: direct pytest invocation without dangerous plugin/exec flags
    if exe == "pytest":
        forbidden_pytest_flags = {"-o", "--override-ini", "--rootdir", "--confcutdir"}
        return not any(arg in forbidden_pytest_flags or arg.startswith("-o") for arg in argv[1:])

    # Case 2: python / python3 -m pytest ... or python3 -m unittest ...
    if exe in ("python", "python3") and len(argv) >= 3 and argv[1] == "-m":
        runner = argv[2]
        if runner in ("pytest", "unittest"):
            forbidden_flags = {"-c", "-o", "--override-ini"}
            return not any(arg in forbidden_flags for arg in argv[3:])

    return False


@dataclass(frozen=True, slots=True)
class CapabilityCaveat:
    """Immutable constraint block restricting a capability token's authority."""

    allowed_tools: FrozenSet[str]
    path_prefixes: Tuple[str, ...]
    denied_paths: Tuple[str, ...] = (
        ".git/hooks",
        ".env",
        ".ssh",
        "src/activesec",
        "audit_vault",
        ".audit.jsonl",
    )
    allowed_binaries: FrozenSet[str] = frozenset()
    network_destinations: FrozenSet[str] = frozenset()
    max_calls: int = 10
    expires_at_unix: float = 0.0
    require_untainted_context: bool = True
    max_information_class: InformationClass = InformationClass.DERIVED

    def canonical_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-serializable dictionary for cryptographic signing."""
        return {
            "allowed_binaries": sorted(self.allowed_binaries),
            "allowed_tools": sorted(self.allowed_tools),
            "denied_paths": list(self.denied_paths),
            "expires_at_unix": round(self.expires_at_unix, 6),
            "max_calls": self.max_calls,
            "max_information_class": self.max_information_class.value,
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
        self._consumed_nonces: set[str] = set()
        self._issued_tokens: dict[str, CapabilityToken] = {}

    def get_call_count(self, token_id: str) -> int:
        """Return the number of verified tool invocations recorded for ``token_id``."""
        return int(self._call_counts.get(token_id, 0))

    def is_revoked(self, token_id: str) -> bool:
        """Return True if ``token_id`` has been revoked."""
        return token_id in self._revoked_tokens

    @classmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        return ComponentSecurityAssessment(
            component_id="capability_token",
            title="Ring-0 Sudo Capability Token, 5-Level IFC Lattice & Attenuation Engine",
            ring_level=0,
            source_path="src/activesec/core/capability_token.py",
            security_test_path="tests/security/test_sec_capability_token.py",
            threat_vectors=("A.1", "A.3", "F.2", "F.3"),
            summary=(
                "Enforces cryptographic sudo capability chains with Macaroon-style chained HMAC-SHA256 "
                "signatures, monotonic attenuation on sub-agent delegation, canonical path confinement, "
                "atomic call-quota/nonce tracking, parent-chain binding, and a 5-level Information-Flow "
                "Taint Lattice (TRUSTED, SANITIZED, DERIVED, UNTRUSTED, SENSITIVE) with fine-grained "
                "action-class permissions."
            ),
            enforced_invariants=(
                "All tokens are signed with a >=256-bit Ring-0 secret using constant-time hmac.compare_digest.",
                "Delegation strictly narrows authority: Child tools, binaries, network targets, paths, TTL, quotas, and max_information_class must be a mathematical subset of the parent token.",
                "Canonical path resolution (os.path.realpath) prevents ../ traversal and protects Ring-0 harness source and dotfiles.",
                "Enforces the 5-level InformationClass lattice: DERIVED taint permits workspace read/write and isolated pytest/unittest runs while blocking arbitrary shell escapes and network egress; UNTRUSTED and SENSITIVE contexts block privileged execution and exfiltration.",
                "Tracks per-call nonces and transitive parent-chain quotas atomically to defeat replay and sub-token quota amplification.",
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
        tok = CapabilityToken(
            token_id=token_id,
            parent_token_id=None,
            issuer_ring=1,
            subject_agent_id=subject_agent_id,
            task_purpose=task_purpose,
            caveats=caveats,
            signature=signature,
        )
        self._issued_tokens[token_id] = tok
        return tok

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

        # 6. Verify TTL, call quota, and InformationClass lattice narrowing
        if narrowed_caveat.expires_at_unix > effective_parent.expires_at_unix:
            raise CapabilityViolationError(
                "Attenuation violation: child token TTL exceeds parent token expiration.",
                vector_id="F.3",
                component_id="capability_token",
            )
        parent_used = self._call_counts.get(parent_token.token_id, 0)
        parent_remaining = max(0, effective_parent.max_calls - parent_used)
        if narrowed_caveat.max_calls > effective_parent.max_calls or narrowed_caveat.max_calls > parent_remaining:
            raise CapabilityViolationError(
                "Attenuation violation: child token max_calls exceeds parent remaining quota.",
                vector_id="F.3",
                component_id="capability_token",
            )
        if effective_parent.require_untainted_context and not narrowed_caveat.require_untainted_context:
            raise CapabilityViolationError(
                "Attenuation violation: child token cannot disable require_untainted_context.",
                vector_id="F.2",
                component_id="capability_token",
            )
        if narrowed_caveat.max_information_class.lattice_rank > effective_parent.max_information_class.lattice_rank:
            raise CapabilityViolationError(
                f"Attenuation violation: child max_information_class '{narrowed_caveat.max_information_class.value}' "
                f"exceeds parent '{effective_parent.max_information_class.value}'.",
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
        child_tok = CapabilityToken(
            token_id=child_id,
            parent_token_id=parent_token.token_id,
            issuer_ring=min(3, parent_token.issuer_ring + 1),
            subject_agent_id=child_agent_id,
            task_purpose=child_purpose,
            caveats=combined_caveats,
            signature=signature,
        )
        self._issued_tokens[child_id] = child_tok
        return child_tok

    def revoke_token(self, token_id: str, *, revoke_entire_lineage: bool = True) -> None:
        """Immediately revoke a token ID and, by default, its entire ancestor/descendant lineage."""
        self._revoked_tokens.add(token_id)
        if not revoke_entire_lineage:
            return

        # 1. Walk up to the root of the lineage if tracked in _issued_tokens
        root_id = token_id
        visited: set[str] = {token_id}
        while True:
            tok_obj = self._issued_tokens.get(root_id)
            if tok_obj is None or tok_obj.parent_token_id is None or tok_obj.parent_token_id in visited:
                break
            root_id = tok_obj.parent_token_id
            visited.add(root_id)
        self._revoked_tokens.add(root_id)

        # 2. Revoke every issued token whose ancestor chain touches root_id or token_id
        for cand_id, cand_tok in self._issued_tokens.items():
            curr = cand_tok.parent_token_id
            chain_seen: set[str] = {cand_id}
            while curr is not None and curr not in chain_seen:
                if curr in self._revoked_tokens:
                    self._revoked_tokens.add(cand_id)
                    break
                chain_seen.add(curr)
                parent_obj = self._issued_tokens.get(curr)
                curr = parent_obj.parent_token_id if parent_obj is not None else None

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
        # Walk transitive ancestor chain if registered in engine
        curr_parent_id = token.parent_token_id
        visited: set[str] = {token.token_id}
        while curr_parent_id is not None:
            if curr_parent_id in self._revoked_tokens:
                raise CapabilityViolationError(
                    f"Ancestor token '{curr_parent_id}' in chain of '{token.token_id}' has been revoked.",
                    vector_id="A.1",
                    component_id="capability_token",
                )
            if curr_parent_id in visited:
                break
            visited.add(curr_parent_id)
            parent_obj = self._issued_tokens.get(curr_parent_id)
            curr_parent_id = parent_obj.parent_token_id if parent_obj is not None else None

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
        raw_command: Optional[str] = None,
        network_destination: Optional[str] = None,
        context_tainted: bool = False,
        information_class: Optional[InformationClass] = None,
        call_nonce: Optional[str] = None,
        current_time: Optional[float] = None,
    ) -> None:
        """Verify every caveat in the token chain and 5-level IFC lattice for a concrete tool invocation."""
        self._verify_signature_and_revocation(token)

        if token.subject_agent_id != agent_id:
            raise CapabilityViolationError(
                f"Token subject mismatch: bound to '{token.subject_agent_id}', used by '{agent_id}'.",
                vector_id="F.3",
                component_id="capability_token",
            )

        if call_nonce is not None:
            nonce_key = f"{token.token_id}:{call_nonce}"
            if nonce_key in self._consumed_nonces:
                raise CapabilityViolationError(
                    f"Replay attack detected: call_nonce '{call_nonce}' has already been consumed.",
                    vector_id="A.3",
                    component_id="capability_token",
                )

        # Resolve effective 5-level InformationClass (maintaining backward compatibility with context_tainted: bool)
        if information_class is not None:
            effective_info_class = (
                information_class.join(InformationClass.UNTRUSTED)
                if context_tainted
                else information_class
            )
        else:
            effective_info_class = (
                InformationClass.UNTRUSTED if context_tainted else InformationClass.TRUSTED
            )

        action_class = classify_tool_action(
            tool_name,
            binary_name=binary_name,
            raw_command=raw_command,
        )
        allowed_actions = ALLOWED_ACTIONS_BY_INFO_CLASS[effective_info_class]

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
            if caveat.require_untainted_context:
                if effective_info_class.lattice_rank > caveat.max_information_class.lattice_rank:
                    raise CapabilityViolationError(
                        f"Agent context taint level '{effective_info_class.value}' exceeds caveat "
                        f"max_information_class '{caveat.max_information_class.value}'; tool call blocked.",
                        vector_id="F.2",
                        component_id="capability_token",
                    )
                if action_class not in allowed_actions:
                    raise CapabilityViolationError(
                        f"Information-Flow Control violation: action '{action_class.value}' ({tool_name}) "
                        f"is forbidden under taint level '{effective_info_class.value}'.",
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
                        or os.path.basename(real_target).endswith(normalized_denied)
                    ):
                        raise CapabilityViolationError(
                            f"Target path '{target_path}' matches protected denied path '{denied}'.",
                            vector_id="A.4",
                            component_id="capability_token",
                        )

        # Also check transitive parent call quotas if parent is tracked
        curr_parent_id = token.parent_token_id
        visited_ancestors: list[str] = []
        while curr_parent_id is not None and curr_parent_id not in visited_ancestors:
            parent_obj = self._issued_tokens.get(curr_parent_id)
            if parent_obj is not None:
                parent_used = self._call_counts.get(curr_parent_id, 0)
                parent_max = parent_obj.caveats[-1].max_calls
                if parent_used >= parent_max:
                    raise CapabilityViolationError(
                        f"Ancestor token '{curr_parent_id}' call quota exhausted ({parent_used}/{parent_max}).",
                        vector_id="A.1",
                        component_id="capability_token",
                    )
                visited_ancestors.append(curr_parent_id)
                curr_parent_id = parent_obj.parent_token_id
            else:
                break

        if call_nonce is not None:
            self._consumed_nonces.add(f"{token.token_id}:{call_nonce}")
        self._call_counts[token.token_id] = used_calls + 1
        for anc_id in visited_ancestors:
            self._call_counts[anc_id] = self._call_counts.get(anc_id, 0) + 1
