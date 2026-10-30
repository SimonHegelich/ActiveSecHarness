"""Base SecureComponent contract and self-assessment metadata for the Karpathy Security Wiki.

Every security-relevant class in ActiveSecHarness inherits from SecureComponent and
declares its privilege ring, mitigated attack vectors, deterministic invariants,
and dedicated security test module.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar, Tuple


@dataclass(frozen=True, slots=True)
class ComponentSecurityAssessment:
    """Immutable security assessment contract feeding the automated Karpathy Wiki."""

    component_id: str
    title: str
    ring_level: int
    source_path: str
    security_test_path: str
    threat_vectors: Tuple[str, ...]
    summary: str
    enforced_invariants: Tuple[str, ...]
    residual_risks: Tuple[str, ...]


class SecureComponent(ABC):
    """Abstract base class for all verifiable security components in ActiveSecHarness."""

    _REGISTRY: ClassVar[dict[str, type[SecureComponent]]] = {}

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if not getattr(cls, "__abstractmethods__", None):
            assessment = cls.security_assessment()
            SecureComponent._REGISTRY[assessment.component_id] = cls

    @classmethod
    @abstractmethod
    def security_assessment(cls) -> ComponentSecurityAssessment:
        """Return the static security assessment metadata for this component."""

    @classmethod
    def registered_components(cls) -> dict[str, type[SecureComponent]]:
        """Return a copy of all registered concrete SecureComponent subclasses."""
        return dict(cls._REGISTRY)
