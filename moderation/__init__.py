"""Interactive moderation tool for MUD and BBS server lists.

Combines dead-entry pruning, within-list duplicate detection, cross-list
conflict resolution, and encoding issue discovery into a single workflow.
"""

from .cli import main

__all__ = ["main"]
