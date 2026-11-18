"""Functional-test handlers, one mixin per test-ID namespace.

The IDs keep their functional namespace (``env.*``, ``parser.*``,
``protocol.*``, ``validation.*``, ``write.*``) and the runner still resolves a
handler with ``getattr(self, f"_test_{id}")``; the methods are simply defined in
the module that owns the namespace.
"""

from __future__ import annotations

from .env import EnvHandlersMixin
from .parser import ParserHandlersMixin
from .protocol import ProtocolHandlersMixin
from .validation import ValidationHandlersMixin
from .write import WriteHandlersMixin

__all__ = [
    "EnvHandlersMixin",
    "ParserHandlersMixin",
    "ProtocolHandlersMixin",
    "ValidationHandlersMixin",
    "WriteHandlersMixin",
]
