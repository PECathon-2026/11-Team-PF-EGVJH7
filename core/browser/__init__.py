"""Public interface for browser operations."""
from .snapshot import take_snapshot
from .executor import execute_action, ExecutionError
__all__ = [
    "take_snapshot",
    "execute_action",
    "ExecutionError",
]
