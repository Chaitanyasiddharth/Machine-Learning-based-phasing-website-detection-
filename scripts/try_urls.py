"""Send sample URLs through the real API (in-process) with the trained model.

These hand-written examples are a smoke test only, not an evaluation. The
phishing-style examples are invented patterns, not live phishing sites.
History is not saved for these calls.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient  # noqa: E402

from api.main import app  # noqa: E402

SAMPLES = [
    "https://www.google.com/search?q=weather",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://github.com/scikit-learn/scikit-learn",
    "https://www.amazon.in/gp/cart/view.html",
    "https://accounts.google.com/signin",
    "http://paypal.com.account-verify-login.xyz/webscr?cmd=_login",
    "http://192.168.12.7/secure/bank/update.php",
    "https://appleid.apple.com.verify-account-security.top/signin",
    "http://login-microsoftonline.support-reset.cf/owa/",
    "bit.ly/3xYz9Ab",
    "javascript:alert(1)",
]

with TestClient(app) as c:
    for url in SAMPLES:
        r = c.post("/api/url/analyze", json={"url": url, "save_to_history": False})
        if r.status_code != 200:
            print(f"{r.status_code}  {url}\n      -> {r.json()['detail']}")
            continue
        b = r.json()
        print(f"{b['prediction']:<10} p={b['phishing_probability']:.3f}  {b['risk_category']:<11}  {url}")
        for i in b["indicators"]:
            print(f"      [{i['severity']}] {i['message']}")
        top = ", ".join(f"{m['feature']} ({m['direction'].split()[-1]})" for m in b["model_reasons"][:3])
        print(f"      model: {top}")
