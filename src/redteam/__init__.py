"""redteam-suite — automated adversarial robustness testing for LLM applications.

Run it only against systems you own or are explicitly authorised to test.
"""

__version__ = "0.1.0"

from .types import (  # noqa: F401
    Attempt,
    Conversation,
    Objective,
    Response,
    Role,
    Severity,
    Turn,
    Verdict,
)

__all__ = [
    "Attempt",
    "Conversation",
    "Objective",
    "Response",
    "Role",
    "Severity",
    "Turn",
    "Verdict",
    "__version__",
]
