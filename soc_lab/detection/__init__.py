"""Detection rules and the engine that runs them."""

from .engine import RULE_REGISTRY, run_detection

__all__ = ["RULE_REGISTRY", "run_detection"]
