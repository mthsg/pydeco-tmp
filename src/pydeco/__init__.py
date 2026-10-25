"""pydeco - control TP-Link Deco routers locally over the TMP protocol (without the app).

Reverse-engineered from the official app and verified against a captured live session.
Public API: :class:`DecoClient`, :func:`keychain`, :class:`DecoError`, plus the registries
:data:`pydeco.opcodes.READ` / :data:`pydeco.opcodes.WRITE`.
"""
from .client import DecoClient, keychain
from .transport import DecoError, DecoTransport

__version__ = "0.2.0"
__all__ = ["DecoClient", "DecoError", "DecoTransport", "keychain"]
