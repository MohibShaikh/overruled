"""overruled: the verdict auditor for AI SOC agents.

overruled replays security cases with known ground truth against an AI SOC
agent, then scores the agent's verdicts for correctness, fabricated
evidence, missed evidence, and consistency.
"""

from importlib.metadata import version as _version

__version__ = _version("overruled")
