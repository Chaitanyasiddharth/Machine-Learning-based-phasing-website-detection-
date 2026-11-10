# PhishGuard AI — Prototype v0.1 (Phase 1: URL detection)

ML-based phishing URL detection with a FastAPI backend and a React dashboard. Phase 1 of the PRD, plus the dashboard for the URL module.

## Module status

| Module | Status |
|---|---|
| 1. Phishing URL detection | **Implemented** (Logistic Regression served; Random Forest trained for comparison) |
| 2. Fake website analysis | Planned (Phase 3) — not started |
| 3. Social engineering detection | Planned (Phase 4) — not started |
| 4. Risk assessment engine | Partial — URL-only risk bands; multi-module aggregation planned |
| 5. Explainability & reporting | Partial — per-URL indicators + model reasons, SQLite history |
| 6. React dashboard | **Partial** — Dashboard, URL Scanner, History, Model & Settings work; Website/Message Analyzer pages are labelled "Planned" |

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python scripts/train_url_model.py      # ~1.5 h on a laptop; --sample 40000 for a quick run
.venv/bin/python -m pytest                        # 17 tests
.venv/bin/python scripts/try_urls.py              # sample URLs through the API
.venv/bin/uvicorn api.main:app --reload           # API docs: http://127.0.0.1:8000/docs
```

### Website
```bash
cd frontend && npm install && npm run build       # FastAPI then serves the site at http://127.0.0.1:8000
npm run dev                                       # or: live-reload dev server on :5173 (proxies /api to :8000)
```
Pages: Dashboard (counts from saved history only), URL Scanner, Analysis History with detail view,
Model & Settings (datasets, metrics, risk bands, limitations), and placeholder pages for the two planned modules.

API: `POST /api/url/analyze {"url": ...}`, `GET /api/history`, `GET /api/history/{id}`,
`GET /api/stats`, `GET /api/info`, `GET /api/health`.

## Data

The PRD's dataset `semihGuner2002/PhishingURLsDataset` is gated on Hugging Face, so these public ones are used instead:

- **Train/validation/test:** `ealvaradob/phishing-dataset` (`urls.json`, Apache-2.0, label 1 = phishing per its card).
  835,697 rows → 796,133 after de-duplication on a normalised URL and dropping 42 URLs with conflicting labels.
- **External test:** `pirocheto/phishing-url` (CC-BY-4.0), 11,070 URLs after cleaning. 11,068 of these also appeared in the
  main dataset and were **removed from it**, so the external test contains no URL the model was trained on. It is a separate
  collection, but not fully independent: both draw on public phishing feeds.

### Leakage controls
- **Domain-grouped split** (80/10/10): no registrable domain appears in more than one of train / validation / test.
- **Scheme artefact removed:** in the main data 88 % of legitimate URLs have no `http(s)://` vs 55 % of phishing URLs.
  The scheme is stripped before both the TF-IDF and the hand-crafted features so the model cannot learn it.
- Model choice, decision threshold and risk thresholds are all chosen on **validation** data; test sets are scored once.

## Models

- **Logistic Regression** — character 3–5-gram TF-IDF (200k features) + 27 scaled hand-crafted features.
- **Random Forest** — the 27 hand-crafted features only (length, special characters, subdomains, IP host, port,
  punycode, keywords, shortener, host entropy, …).

## Results (full run, 635,666 training URLs)

| Model | Set | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR | FNR |
|---|---|---|---|---|---|---|---|---|
| Logistic Regression | Test (77,005) | 0.923 | 0.893 | 0.937 | 0.915 | 0.981 | 0.088 | 0.063 |
| Logistic Regression | External (11,070) | 0.839 | 0.814 | 0.865 | 0.839 | 0.921 | 0.186 | 0.135 |
| Random Forest | Test (77,005) | 0.914 | 0.904 | 0.898 | 0.901 | 0.972 | 0.074 | 0.102 |
| Random Forest | External (11,070) | 0.709 | 0.674 | 0.771 | 0.719 | 0.798 | 0.350 | 0.229 |

Logistic Regression was selected (validation F1 0.943 vs 0.885). Full metrics, confusion matrices and sampled
errors: `reports/url_model_metrics.json`.

## Known limitations (observed, not hypothetical)

1. **Performance drops on a different collection:** F1 0.915 → 0.839, and 18.6 % of legitimate external URLs are flagged.
2. **Keyword-driven false positives.** `https://accounts.google.com/signin` is classified phishing (p = 0.886, HIGH RISK);
   `https://www.amazon.in/gp/cart/view.html` lands in MEDIUM (p = 0.463). Test false positives include many
   `facebook.com/...` profile URLs. URL text alone cannot tell a real sign-in page from a fake one; this is what the
   website-analysis module and a trusted-domain check are meant to address.
3. **Shorteners score as phishing** (`bit.ly/...` p = 0.998) because the data's shortened links are mostly phishing. A
   shortener only hides the destination; it is not evidence of phishing.
4. **Risk bands need rework.** The validation-derived thresholds (LOW < 0.429 ≤ MEDIUM < 0.493 ≤ HIGH) make MEDIUM
   almost empty (1.7 % of test inputs). On test the HIGH band is 88.7 % phishing and LOW is 4.2 %, missing the 95 %
   target for HIGH; on the external set they are 81.0 % and 11.7 %.
5. Logistic Regression (liblinear) logged a convergence warning at 1000 iterations.
6. `javascript:alert(1)` is rejected correctly (HTTP 422), but the message says "no valid host" instead of "unsupported scheme".

## Security notes
- The URL module is lexical only: it never fetches the URL (no SSRF surface, no script execution).
- Inputs are validated (http/https only, ≤ 2048 chars, no whitespace/control characters).
- History stores URLs with query string, fragment and credentials removed.
- Unhandled errors return a generic message; details go to server logs only.
