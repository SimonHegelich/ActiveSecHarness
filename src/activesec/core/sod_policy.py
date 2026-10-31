"""Ring-0 Compositional Cross-Agent Separation of Duties & Workspace Provenance Ledger.

Implements compositional Information-Flow Control (IFC) across shared workspace state:
1. Per-file provenance labels `\\ell(f) \\in InformationClass` (`TRUSTED`, `SANITIZED`, `DERIVED`,
   `UNTRUSTED`, `SENSITIVE`) paired with side-effect origin tags (`READ_SENSITIVE`,
   `READ_EXTERNAL`, `WRITE_LOCAL`, etc.).
2. When Agent A writes to workspace path `f`, `WorkspaceProvenanceLedger` records
   `\\ell(f) = \\ell(f) \\sqcup \\tau(A)` along with Agent A's active side-effect provenance
   `\\Sigma_A`.
3. When Agent B reads workspace path `f`, Agent B's session taint `\\tau(B)` and side-effect
   provenance `\\Sigma_B` absorb `\\ell(f)` and `\\Sigma(f)`:
   `\\tau(B) \\leftarrow \\tau(B) \\sqcup \\ell(f)` and `\\Sigma_B \\leftarrow \\Sigma_B \\cup \\Sigma(f)`.
4. Consequently, Agent A (`READ_SENSITIVE` -> `fs:write(f)`) followed by Agent B
   (`fs:read(f)` -> `net:https` or `shell:exec`) is deterministically blocked as a
   compositional Lethal Trifecta (`ToxicCombinationError`, `vector_id="F.3"`), unless `f`
   passes through an explicit Ring-0/1 deterministic declassifier (`declassify_artifact` -> `SANITIZED`).
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional, Set, Tuple

from activesec.core.capability_token import (
    ALLOWED_ACTIONS_BY_INFO_CLASS,
    ActionClass,
    CompositeLabel,
    InformationClass,
    SensitivityLevel,
    TrustLevel,
    classify_tool_action,
)
from activesec.core.component import ComponentSecurityAssessment, SecureComponent
from activesec.core.exceptions import CapabilityViolationError, ToxicCombinationError


DEFAULT_SENSITIVE_PATH_MARKERS: Tuple[str, ...] = (
    "secret",
    "credential",
    "token",
    "private",
    "internal",
    "confidential",
    "apikey",
    "api_key",
    "passwd",
    "password",
    ".env",
    "id_rsa",
    "id_ed25519",
)

DEFAULT_UNTRUSTED_PATH_MARKERS: Tuple[str, ...] = (
    "untrusted",
    "external",
    "issue_",
    "pr_",
    "webhook",
    "downloaded",
    "extracted",
    "inbox",
)


@dataclass(frozen=True, slots=True)
class ArtifactProvenanceRecord:
    """Immutable provenance tag attached to a canonical workspace file path."""

    canonical_path: str
    information_class: InformationClass
    origin_side_effects: FrozenSet[str]
    written_by_agent: str
    updated_at_unix: float
    content_sha256: str
    declassified_by_ring: Optional[int] = None
    composite_label: CompositeLabel = CompositeLabel(TrustLevel.TRUSTED, SensitivityLevel.PUBLIC)


@dataclass(slots=True)
class AgentFlowState:
    """Mutable per-agent session information-flow and side-effect state."""

    agent_id: str
    information_class: InformationClass = InformationClass.TRUSTED
    composite_label: CompositeLabel = CompositeLabel(TrustLevel.TRUSTED, SensitivityLevel.PUBLIC)
    absorbed_side_effects: Set[str] = field(default_factory=set)
    touched_files: Set[str] = field(default_factory=set)


class WorkspaceProvenanceLedger(SecureComponent):
    """Ring-0 ledger tracking per-file provenance `\\ell(f)` and cross-agent compositional SoD."""

    INCOMPATIBLE_PROVENANCE_AND_EFFECTS: FrozenSet[FrozenSet[str]] = frozenset(
        {
            frozenset({"READ_SENSITIVE", "NETWORK_EGRESS"}),
            frozenset({"READ_SENSITIVE", "EXEC_PROCESS"}),
            frozenset({"READ_EXTERNAL", "NETWORK_EGRESS"}),
            frozenset({"READ_EXTERNAL", "EXEC_PROCESS"}),
        }
    )

    def __init__(self, *, workspace_dir: Optional[str] = None) -> None:
        self._workspace_dir: Optional[str] = (
            os.path.realpath(workspace_dir) if workspace_dir is not None else None
        )
        self._file_records: Dict[str, ArtifactProvenanceRecord] = {}
        self._agent_states: Dict[str, AgentFlowState] = {}

    @classmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        return ComponentSecurityAssessment(
            component_id="sod_policy",
            title="Ring-0 Workspace Provenance Ledger & Compositional Multi-Agent SoD Engine",
            ring_level=0,
            source_path="src/activesec/core/sod_policy.py",
            security_test_path="tests/security/test_sec_sod_policy.py",
            threat_vectors=("C.2", "D.2", "F.2", "F.3"),
            summary=(
                "Enforces compositional Information-Flow Control (IFC) and Separation of Duties (SoD) "
                "across collaborating agents sharing a workspace filesystem. Tracks per-file provenance "
                "labels l(f) in the 5-level InformationClass lattice and propagates both taint and "
                "side-effect origins (READ_SENSITIVE, READ_EXTERNAL) whenever an agent writes to and "
                "another agent reads from shared workspace files, defeating multi-agent laundering "
                "of the Lethal Trifecta unless explicitly declassified to SANITIZED."
            ),
            enforced_invariants=(
                "Every workspace write by Agent A updates the canonical file's provenance record l(f) = l_prev(f) join tau(A) and unions Agent A's side-effect history Sigma(f) = Sigma_prev(f) U Sigma_A.",
                "Every workspace read of file f by Agent B updates Agent B's flow state tau(B) = tau(B) join l(f) and Sigma_B = Sigma_B U Sigma(f).",
                "Blocks any cross-agent Lethal Trifecta where Agent A reads sensitive or untrusted external data, writes it to a workspace staging file, and Agent B reads that file and attempts NETWORK_EGRESS or arbitrary EXEC_PROCESS.",
                "Permits DERIVED taint workflows (e.g., summarizing an issue into code edits and running isolated pytest/unittest) while blocking arbitrary shell escapes and network exfiltration.",
                "Requires explicit Ring-0/1 deterministic declassification (declassify_artifact -> SANITIZED) before sensitive or untrusted workspace artifacts can be transmitted externally.",
            ),
            residual_risks=(
                "Covert timing channels across process scheduling (mitigated by sequential Ring-0 kernel mediation and deterministic timeout budgets).",
            ),
        )

    def get_agent_state(self, agent_id: str) -> AgentFlowState:
        """Return or initialize the flow state for ``agent_id``."""
        state = self._agent_states.get(agent_id)
        if state is None:
            state = AgentFlowState(agent_id=agent_id)
            self._agent_states[agent_id] = state
        return state

    def get_file_record(self, path: str) -> Optional[ArtifactProvenanceRecord]:
        """Return the provenance record for canonical ``path``, if tracked."""
        real_path = os.path.realpath(path)
        return self._file_records.get(real_path)

    def get_file_label(self, path: str) -> InformationClass:
        """Return the current `InformationClass` label `\\ell(f)` for ``path``."""
        real_path = os.path.realpath(path)
        rec = self._file_records.get(real_path)
        if rec is not None:
            return rec.information_class
        return self._infer_initial_file_label(real_path)

    @staticmethod
    def _infer_initial_file_label(real_path: str) -> InformationClass:
        """Infer initial provenance classification for pre-existing files not yet written in session."""
        lower_base = os.path.basename(real_path).lower()
        lower_full = real_path.lower()
        if any(m in lower_base or m in lower_full for m in DEFAULT_SENSITIVE_PATH_MARKERS):
            return InformationClass.SENSITIVE
        if any(m in lower_base or m in lower_full for m in DEFAULT_UNTRUSTED_PATH_MARKERS):
            return InformationClass.UNTRUSTED
        return InformationClass.TRUSTED

    @classmethod
    def _infer_initial_composite_label(cls, real_path: str) -> CompositeLabel:
        """Infer initial 2D product-lattice label (tau, sigma) for a pre-existing file."""
        lower_base = os.path.basename(real_path).lower()
        lower_full = real_path.lower()
        is_sens = any(m in lower_base or m in lower_full for m in DEFAULT_SENSITIVE_PATH_MARKERS)
        is_untrusted = any(m in lower_base or m in lower_full for m in DEFAULT_UNTRUSTED_PATH_MARKERS)
        return CompositeLabel(
            trust=TrustLevel.UNTRUSTED if is_untrusted else TrustLevel.TRUSTED,
            sensitivity=SensitivityLevel.SENSITIVE if is_sens else SensitivityLevel.PUBLIC,
        )

    def tag_file_provenance(
        self,
        path: str,
        *,
        information_class: InformationClass,
        origin_side_effects: FrozenSet[str] = frozenset(),
        actor_id: str = "ring0-seed",
        content: str = "",
        composite_label: Optional[CompositeLabel] = None,
    ) -> ArtifactProvenanceRecord:
        """Explicitly assign or seed the provenance label `\\ell(f)` for a workspace path."""
        real_path = os.path.realpath(path)
        digest = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
        comp = composite_label if composite_label is not None else information_class.to_composite_label()
        rec = ArtifactProvenanceRecord(
            canonical_path=real_path,
            information_class=information_class,
            origin_side_effects=frozenset(origin_side_effects),
            written_by_agent=actor_id,
            updated_at_unix=time.time(),
            content_sha256=digest,
            composite_label=comp,
        )
        self._file_records[real_path] = rec
        return rec

    def elevate_agent_taint(
        self,
        agent_id: str,
        information_class: InformationClass,
        *,
        side_effects: FrozenSet[str] = frozenset(),
        composite_label: Optional[CompositeLabel] = None,
    ) -> AgentFlowState:
        """Monotonically join ``information_class`` and ``side_effects`` into ``agent_id``'s session state."""
        state = self.get_agent_state(agent_id)
        state.information_class = state.information_class.join(information_class)
        incoming_comp = composite_label if composite_label is not None else information_class.to_composite_label()
        state.composite_label = state.composite_label.join(incoming_comp)
        state.absorbed_side_effects.update(side_effects)
        return state

    def sanitize_agent_representation(self, agent_id: str) -> AgentFlowState:
        """Structural representation cleaning (Definition 3.3 / Proposition A.2).

        Lowers provenance trust tau |-> SANITIZED while leaving confidentiality sigma unchanged
        (so a Sensitive secret is never accidentally declassified by syntax/Unicode cleaning).
        """
        state = self.get_agent_state(agent_id)
        state.composite_label = state.composite_label.sanitize()
        state.information_class = state.composite_label.to_information_class
        if state.composite_label.sensitivity == SensitivityLevel.PUBLIC:
            state.absorbed_side_effects.discard("READ_EXTERNAL")
        return state

    def derive_agent_summary(self, agent_id: str) -> AgentFlowState:
        """Transition an `UNTRUSTED` agent context (e.g. after reading an external issue) to `DERIVED` plan state.

        Note: `SENSITIVE` data cannot be downgraded to `DERIVED` without explicit declassification;
        only `UNTRUSTED` external input transitions to `DERIVED` structured plan/edit state.
        """
        state = self.get_agent_state(agent_id)
        if (
            state.information_class == InformationClass.SENSITIVE
            or state.composite_label.sensitivity == SensitivityLevel.SENSITIVE
        ):
            raise CapabilityViolationError(
                f"Cannot downgrade SENSITIVE provenance for agent '{agent_id}' to DERIVED without declassification.",
                vector_id="F.2",
                component_id="sod_policy",
            )
        state.information_class = InformationClass.DERIVED
        state.composite_label = CompositeLabel(
            trust=TrustLevel.DERIVED,
            sensitivity=state.composite_label.sensitivity,
        )
        state.absorbed_side_effects.discard("READ_EXTERNAL")
        return state

    def declassify_artifact(
        self,
        path: str,
        *,
        authorized_by_ring: int = 1,
        sanitized_content: str = "",
    ) -> ArtifactProvenanceRecord:
        """Explicitly declassify a workspace file to `(SANITIZED, PUBLIC)` after deterministic DLP scrubbing or Ring-1 review."""
        if authorized_by_ring not in (0, 1):
            raise CapabilityViolationError(
                f"Artifact declassification requires Ring 0 or Ring 1 authority (got Ring {authorized_by_ring}).",
                vector_id="F.3",
                component_id="sod_policy",
            )
        real_path = os.path.realpath(path)
        digest = hashlib.sha256(sanitized_content.encode("utf-8", errors="replace")).hexdigest()
        rec = ArtifactProvenanceRecord(
            canonical_path=real_path,
            information_class=InformationClass.SANITIZED,
            origin_side_effects=frozenset(),
            written_by_agent=f"ring{authorized_by_ring}-declassifier",
            updated_at_unix=time.time(),
            content_sha256=digest,
            declassified_by_ring=authorized_by_ring,
            composite_label=CompositeLabel(TrustLevel.SANITIZED, SensitivityLevel.PUBLIC),
        )
        self._file_records[real_path] = rec
        return rec

    def record_file_read(
        self,
        *,
        agent_id: str,
        path: str,
        explicit_file_class: Optional[InformationClass] = None,
    ) -> AgentFlowState:
        """Propagate provenance `\\ell(f)` and `\\Sigma(f)` from file ``path`` into ``agent_id`` upon `fs:read`."""
        real_path = os.path.realpath(path)
        state = self.get_agent_state(agent_id)
        rec = self._file_records.get(real_path)

        if rec is not None:
            file_class = rec.information_class
            file_comp = rec.composite_label
            file_effects = set(rec.origin_side_effects)
        else:
            file_class = (
                explicit_file_class
                if explicit_file_class is not None
                else self._infer_initial_file_label(real_path)
            )
            file_comp = (
                explicit_file_class.to_composite_label()
                if explicit_file_class is not None
                else self._infer_initial_composite_label(real_path)
            )
            file_effects = set()
            if file_class == InformationClass.SENSITIVE or file_comp.sensitivity == SensitivityLevel.SENSITIVE:
                file_effects.add("READ_SENSITIVE")
            if file_class == InformationClass.UNTRUSTED or file_comp.trust == TrustLevel.UNTRUSTED:
                file_effects.add("READ_EXTERNAL")

        state.information_class = state.information_class.join(file_class)
        state.composite_label = state.composite_label.join(file_comp)
        state.absorbed_side_effects.update(file_effects)
        state.touched_files.add(real_path)
        return state

    def record_file_write(
        self,
        *,
        agent_id: str,
        path: str,
        content: str = "",
        explicit_class: Optional[InformationClass] = None,
    ) -> ArtifactProvenanceRecord:
        """Propagate ``agent_id``'s current taint `\\tau(A)` and `\\Sigma_A` onto workspace file ``path``."""
        real_path = os.path.realpath(path)
        state = self.get_agent_state(agent_id)

        effective_class = state.information_class
        effective_comp = state.composite_label
        if explicit_class is not None:
            effective_class = effective_class.join(explicit_class)
            effective_comp = effective_comp.join(explicit_class.to_composite_label())

        existing = self._file_records.get(real_path)
        if existing is not None and existing.declassified_by_ring is None:
            effective_class = effective_class.join(existing.information_class)
            effective_comp = effective_comp.join(existing.composite_label)
            combined_effects = set(existing.origin_side_effects) | set(state.absorbed_side_effects)
        else:
            combined_effects = set(state.absorbed_side_effects)

        combined_effects.add("WRITE_LOCAL")
        if effective_class == InformationClass.SENSITIVE or effective_comp.sensitivity == SensitivityLevel.SENSITIVE:
            combined_effects.add("READ_SENSITIVE")
        if effective_class == InformationClass.UNTRUSTED or effective_comp.trust == TrustLevel.UNTRUSTED:
            combined_effects.add("READ_EXTERNAL")

        digest = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
        rec = ArtifactProvenanceRecord(
            canonical_path=real_path,
            information_class=effective_class,
            origin_side_effects=frozenset(combined_effects),
            written_by_agent=agent_id,
            updated_at_unix=time.time(),
            content_sha256=digest,
            composite_label=effective_comp,
        )
        self._file_records[real_path] = rec
        state.touched_files.add(real_path)
        return rec

    def verify_compositional_action(
        self,
        *,
        agent_id: str,
        tool_name: str,
        target_path: Optional[str] = None,
        binary_name: Optional[str] = None,
        raw_command: Optional[str] = None,
        explicit_information_class: Optional[InformationClass] = None,
    ) -> InformationClass:
        """Verify that ``agent_id`` executing ``tool_name`` does not violate compositional IFC or SoD.

        Returns the effective `InformationClass` for the operation after considering both the
        agent's accumulated flow state and any target file being read.
        """
        state = self.get_agent_state(agent_id)
        effective_class = state.information_class
        effective_comp = state.composite_label
        if explicit_information_class is not None:
            effective_class = effective_class.join(explicit_information_class)
            effective_comp = effective_comp.join(explicit_information_class.to_composite_label())

        active_effects = set(state.absorbed_side_effects)

        # If reading a file, preview its provenance before execution
        if tool_name == "fs:read" and target_path:
            real_path = os.path.realpath(target_path)
            rec = self._file_records.get(real_path)
            if rec is not None:
                effective_class = effective_class.join(rec.information_class)
                effective_comp = effective_comp.join(rec.composite_label)
                active_effects.update(rec.origin_side_effects)
            else:
                inferred = self._infer_initial_file_label(real_path)
                inferred_comp = self._infer_initial_composite_label(real_path)
                effective_class = effective_class.join(inferred)
                effective_comp = effective_comp.join(inferred_comp)
                if inferred == InformationClass.SENSITIVE or inferred_comp.sensitivity == SensitivityLevel.SENSITIVE:
                    active_effects.add("READ_SENSITIVE")
                if inferred == InformationClass.UNTRUSTED or inferred_comp.trust == TrustLevel.UNTRUSTED:
                    active_effects.add("READ_EXTERNAL")

        action_class = classify_tool_action(
            tool_name,
            binary_name=binary_name,
            raw_command=raw_command,
        )

        # Map action_class to side-effect domain for Compositional Lethal Trifecta detection
        requested_effect: Optional[str] = None
        if action_class == ActionClass.NETWORK_EGRESS:
            requested_effect = "NETWORK_EGRESS"
        elif action_class == ActionClass.SHELL_ARBITRARY:
            requested_effect = "EXEC_PROCESS"

        if requested_effect is not None:
            for prior_eff in sorted(active_effects):
                if frozenset({prior_eff, requested_effect}) in self.INCOMPATIBLE_PROVENANCE_AND_EFFECTS:
                    raise ToxicCombinationError(
                        f"Compositional Separation-of-Duties (SoD) violation for agent '{agent_id}': "
                        f"workspace provenance carries '{prior_eff}' (taint={effective_class.value}) "
                        f"which cannot be combined with '{requested_effect}' ({tool_name}) across shared state.",
                        vector_id="F.3",
                        component_id="sod_policy",
                    )

        allowed_actions = ALLOWED_ACTIONS_BY_INFO_CLASS[effective_class] & effective_comp.allowed_actions
        if action_class not in allowed_actions:
            if effective_class in (InformationClass.SENSITIVE, InformationClass.UNTRUSTED) and action_class in (
                ActionClass.NETWORK_EGRESS,
                ActionClass.SHELL_ARBITRARY,
            ):
                raise ToxicCombinationError(
                    f"Compositional IFC/SoD violation: agent '{agent_id}' with provenance "
                    f"'{effective_class.value}' cannot execute '{action_class.value}' ({tool_name}).",
                    vector_id="F.3",
                    component_id="sod_policy",
                )
            raise CapabilityViolationError(
                f"Compositional IFC violation: action '{action_class.value}' ({tool_name}) "
                f"is not permitted under provenance level '{effective_class.value}' ({effective_comp.trust.value}, {effective_comp.sensitivity.value}).",
                vector_id="F.2",
                component_id="sod_policy",
            )

        return effective_class
