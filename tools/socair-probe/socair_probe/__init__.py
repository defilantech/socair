"""socair-probe: a Tier 2 probe helper for Socair.

It speaks the socair.tier2/v1 protocol (docs/tier2.md): Socair writes a
request to standard input, and the helper drives an OpenAI-compatible
inference endpoint and writes its measurements to standard output.
"""

__version__ = "0.1.0"
