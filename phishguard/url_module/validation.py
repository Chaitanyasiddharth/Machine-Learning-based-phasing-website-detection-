"""Input validation and normalisation for the URL detection module.

The URL module is purely lexical: it never fetches or resolves the URL, so it
cannot be used for SSRF. Validation exists to reject garbage / oversized input
and unsupported schemes before feature extraction.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = {"http", "https"}
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_HOST_RE = re.compile(r"^[A-Za-z0-9.\-_\[\]:]+$")


class URLValidationError(ValueError):
    """Raised when user input is not an analysable URL."""


@dataclass(frozen=True)
class ValidatedURL:
    raw: str          # trimmed input as the user gave it
    parsed_url: str   # with an http:// scheme added if none was given (used for parsing only)
    had_scheme: bool
    scheme: str
    host: str


def validate_url(value: str) -> ValidatedURL:
    if not isinstance(value, str):
        raise URLValidationError("URL must be a string.")
    raw = value.strip()
    if not raw:
        raise URLValidationError("URL is empty.")
    if len(raw) > MAX_URL_LENGTH:
        raise URLValidationError(f"URL is longer than {MAX_URL_LENGTH} characters.")
    if any(ch.isspace() for ch in raw) or any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        raise URLValidationError("URL must not contain whitespace or control characters.")

    had_scheme = bool(_SCHEME_RE.match(raw))
    candidate = raw if had_scheme else "http://" + raw
    try:
        parts = urlsplit(candidate)
    except ValueError as exc:
        raise URLValidationError("URL could not be parsed.") from exc

    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise URLValidationError(f"Unsupported URL scheme '{scheme}'. Only http and https are accepted.")
    host = (parts.hostname or "").lower()
    if not host or "." not in host.strip("[]") and ":" not in host:
        raise URLValidationError("URL must contain a valid host name (e.g. example.com).")
    if not _HOST_RE.match(host):
        # Non-ASCII hosts are allowed through IDNA so punycode can still be flagged.
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise URLValidationError("URL host contains invalid characters.") from exc

    return ValidatedURL(raw=raw, parsed_url=candidate, had_scheme=had_scheme, scheme=scheme, host=host)


def redact_for_storage(v: ValidatedURL) -> str:
    """Strip credentials, query string and fragment before persisting a URL to history.

    Query strings frequently carry tokens / e-mail addresses, so we keep only
    scheme, host, port and path.
    """
    parts = urlsplit(v.parsed_url)
    netloc = parts.hostname or ""
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    redacted = urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    if parts.query or parts.fragment or parts.username:
        redacted += "  [query/credentials removed]"
    return redacted if v.had_scheme else redacted.split("://", 1)[1]
