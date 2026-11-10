"""Unit tests for validation, feature extraction and API plumbing.

The API test trains a throwaway model on a handful of toy URLs purely to exercise
the request/response/history path. It says nothing about detection quality.
"""
import joblib
import pytest
from fastapi.testclient import TestClient

from phishguard.url_module.features import FEATURE_NAMES, describe_indicators, extract_features, normalize_for_tfidf
from phishguard.url_module.model import BUNDLE_VERSION, build_logistic_regression
from phishguard.url_module.validation import URLValidationError, redact_for_storage, validate_url


@pytest.mark.parametrize("bad", ["", "   ", "javascript:alert(1)", "ftp://example.com/x", "file:///etc/passwd",
                                 "http://", "not a url", "http://exa mple.com", "x" * 3000, "nodot"])
def test_rejects_invalid(bad):
    with pytest.raises(URLValidationError):
        validate_url(bad)


def test_accepts_schemeless_and_https():
    v = validate_url("example.com/login")
    assert not v.had_scheme and v.host == "example.com"
    assert validate_url("HTTPS://Example.com").scheme == "https"


def test_features():
    f = extract_features("http://192.168.0.1:8080/paypal/login@verify//x")
    assert set(f) == set(FEATURE_NAMES)
    assert f["host_has_ip"] == 1 and f["has_port"] == 1 and f["num_at"] == 1
    assert f["num_suspicious_keywords"] >= 2 and f["double_slash_in_path"] == 1
    g = extract_features("a.b.c.d.example.co")
    assert g["num_subdomains"] == 4 and g["host_has_ip"] == 0
    assert extract_features("xn--pple-43d.com")["has_punycode"] == 1


def test_normalize_strips_scheme_and_www():
    assert normalize_for_tfidf("HTTPS://WWW.Example.com/A") == "example.com/a"


def test_indicators():
    codes = {i["code"] for i in describe_indicators("http://10.0.0.1/secure-login", True, "http")}
    assert {"ip_host", "keywords", "no_https"} <= codes
    assert describe_indicators("wikipedia.org", False, None) == []


def test_redaction_removes_query_and_credentials():
    r = redact_for_storage(validate_url("https://user:pw@ex.com/p?token=abc#f"))
    assert "pw" not in r and "token" not in r and r.startswith("https://ex.com/p")


@pytest.fixture
def client(tmp_path, monkeypatch):
    urls = ["google.com", "wikipedia.org/wiki/Python", "github.com/user/repo", "bbc.co.uk/news"] * 5 + \
           ["paypal-secure-login.tk/verify", "192.168.1.5/bank/login", "apple.id-verify-account.xyz",
            "secure-update-billing.com/signin"] * 5
    y = [0] * 20 + [1] * 20
    pipe = build_logistic_regression(max_features=500)
    pipe.named_steps["features"].transformer_list[0][1].named_steps["tfidf"].min_df = 1
    pipe.fit(urls, y)
    tfidf = pipe.named_steps["features"].transformer_list[0][1].named_steps["tfidf"]
    names = [f"char_tfidf__{n}" for n in tfidf.get_feature_names_out()] + [f"handcrafted__{n}" for n in FEATURE_NAMES]
    model_path = tmp_path / "m.joblib"
    joblib.dump({"bundle_version": BUNDLE_VERSION, "model": pipe, "model_name": "toy", "decision_threshold": 0.5,
                 "risk_thresholds": {"low": 0.3, "high": 0.7}, "feature_names": names}, model_path)
    monkeypatch.setenv("PHISHGUARD_MODEL", str(model_path))
    monkeypatch.setenv("PHISHGUARD_DB", str(tmp_path / "h.db"))
    import importlib

    import api.main
    importlib.reload(api.main)
    with TestClient(api.main.app) as c:
        yield c


def test_api_roundtrip(client):
    r = client.post("/api/url/analyze", json={"url": "http://10.1.1.1/secure-login?email=a@b.c"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["prediction"] in {"phishing", "legitimate"}
    assert body["risk_category"] in {"LOW RISK", "MEDIUM RISK", "HIGH RISK"}
    assert 0 <= body["phishing_probability"] <= 1 and body["model_reasons"]
    item = client.get(f"/api/history/{body['history_id']}").json()
    assert "email" not in item["input_redacted"]
    assert client.get("/api/stats").json()["total_urls_analyzed"] == 1
    assert client.post("/api/url/analyze", json={"url": "javascript:alert(1)"}).status_code == 422
    assert client.get("/api/history/999").status_code == 404
    assert client.get("/api/info").json()["modules"]["url_detection"] == "implemented"


def test_api_without_model(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHGUARD_MODEL", str(tmp_path / "missing.joblib"))
    monkeypatch.setenv("PHISHGUARD_DB", str(tmp_path / "h.db"))
    import importlib

    import api.main
    importlib.reload(api.main)
    with TestClient(api.main.app) as c:
        assert c.get("/api/health").json()["url_model_loaded"] is False
        assert c.post("/api/url/analyze", json={"url": "example.com"}).status_code == 503
