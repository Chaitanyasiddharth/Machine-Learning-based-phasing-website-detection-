"""Lexical URL feature extraction.

Two kinds of features are produced:
  * hand-crafted numeric features (length, special characters, subdomains, IP
    host, keywords, ...) -> ``extract_features`` / ``HandcraftedFeatures``
  * character n-gram TF-IDF (built in ``model.py``) on ``normalize_for_tfidf``.

``describe_indicators`` turns the hand-crafted features into human-readable
warnings. These are heuristic indicators shown to the user alongside the model
output; they are NOT the model's decision rule.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

SUSPICIOUS_KEYWORDS = (
    "login", "log-in", "signin", "sign-in", "verify", "verification", "account",
    "secure", "security", "update", "confirm", "password", "banking", "wallet",
    "suspend", "unlock", "billing", "webscr", "authenticate", "recover",
)
URL_SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "s.id",
}
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "query_length",
    "num_dots", "num_hyphens", "num_underscores", "num_slashes",
    "num_at", "num_question", "num_equals", "num_ampersand",
    "num_percent", "num_tilde", "num_digits", "digit_ratio",
    "num_subdomains", "host_has_ip", "has_port", "has_punycode",
    "num_suspicious_keywords", "is_shortener", "double_slash_in_path",
    "host_entropy", "host_num_hyphens", "path_depth", "tld_length",
]


def _split(url: str):
    candidate = url if _SCHEME_RE.match(url) else "http://" + url
    try:
        parts = urlsplit(candidate)
        host = (parts.hostname or "").lower()
        port = parts.port  # may raise ValueError on garbage ports
    except ValueError:
        return "", "", "", "", None
    return parts.scheme.lower(), host, parts.path, parts.query, port


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        # Hex / integer encoded IPv4 such as 0x7f000001 or 3232235777
        return bool(re.fullmatch(r"(0x[0-9a-f]+|\d{8,10})", host))


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def extract_features(url: str) -> dict[str, float]:
    url = url.strip()
    _, host, path, query, port = _split(url)
    # Count characters on the URL *without* its scheme, so whether the source
    # stored "http(s)://" (a dataset-collection artefact) does not leak into
    # length / slash / dot counts. HTTPS is reported to users as an indicator only.
    url = _SCHEME_RE.sub("", url)
    lower = url.lower()
    labels = [p for p in host.split(".") if p]
    is_ip = _is_ip(host)
    digits = sum(ch.isdigit() for ch in url)
    return {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),
        "num_at": url.count("@"),
        "num_question": url.count("?"),
        "num_equals": url.count("="),
        "num_ampersand": url.count("&"),
        "num_percent": url.count("%"),
        "num_tilde": url.count("~"),
        "num_digits": digits,
        "digit_ratio": digits / len(url) if url else 0.0,
        # labels beyond registrable "name.tld" (approximation: no public-suffix list)
        "num_subdomains": 0 if is_ip else max(len(labels) - 2, 0),
        "host_has_ip": int(is_ip),
        "has_port": int(port is not None),
        "has_punycode": int("xn--" in host),
        "num_suspicious_keywords": sum(lower.count(k) for k in SUSPICIOUS_KEYWORDS),
        "is_shortener": int(host.removeprefix("www.") in URL_SHORTENERS),
        "double_slash_in_path": int("//" in path),
        "host_entropy": _entropy(host),
        "host_num_hyphens": host.count("-"),
        "path_depth": len([p for p in path.split("/") if p]),
        "tld_length": 0 if is_ip or not labels else len(labels[-1]),
    }


def normalize_for_tfidf(url: str) -> str:
    """Lower-case and drop the scheme and a leading 'www.'.

    The scheme is removed on purpose: phishing datasets often differ in whether
    URLs were stored with/without 'http(s)://' per class, which would let the
    model learn a collection artefact rather than a real signal.
    """
    u = url.strip().lower()
    u = _SCHEME_RE.sub("", u)
    return u.removeprefix("www.")


class HandcraftedFeatures(BaseEstimator, TransformerMixin):
    """sklearn transformer: iterable of URL strings -> dense feature matrix."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return np.array([[f[n] for n in FEATURE_NAMES] for f in map(extract_features, X)], dtype=np.float64)

    def get_feature_names_out(self, input_features=None):
        return np.array(FEATURE_NAMES, dtype=object)


def describe_indicators(url: str, had_scheme: bool | None = None, scheme: str | None = None) -> list[dict]:
    """Human-readable heuristic indicators for the UI / report."""
    f = extract_features(url)
    out: list[dict] = []

    def add(code, severity, message):
        out.append({"code": code, "severity": severity, "message": message})

    if f["host_has_ip"]:
        add("ip_host", "high", "The host is a raw IP address instead of a domain name.")
    if f["num_at"]:
        add("at_symbol", "high", "Contains '@', which can hide the real destination host.")
    if f["has_punycode"]:
        add("punycode", "medium", "Host uses punycode (xn--), which can imitate other characters.")
    if f["num_subdomains"] >= 3:
        add("many_subdomains", "medium", f"Unusually many subdomain levels ({int(f['num_subdomains'])}).")
    if f["url_length"] > 100:
        add("long_url", "low", f"Very long URL ({int(f['url_length'])} characters).")
    if f["num_suspicious_keywords"]:
        found = sorted({k for k in SUSPICIOUS_KEYWORDS if k in url.lower()})
        add("keywords", "medium", "Contains credential/urgency-related words: " + ", ".join(found) + ".")
    if f["host_num_hyphens"] >= 2:
        add("hyphenated_host", "low", "Host name contains several hyphens.")
    if f["is_shortener"]:
        add("shortener", "medium", "Uses a URL-shortening service, which hides the final destination.")
    if f["has_port"]:
        add("explicit_port", "low", "Specifies an explicit port number.")
    if f["double_slash_in_path"]:
        add("double_slash", "low", "Path contains '//', sometimes used for redirection tricks.")
    if f["num_percent"] >= 5:
        add("heavy_encoding", "low", "Heavy percent-encoding may be used to obscure the URL.")
    if had_scheme and scheme == "http":
        add("no_https", "low", "Uses plain HTTP (no TLS). Note: HTTPS alone does not mean a site is safe.")
    return out
