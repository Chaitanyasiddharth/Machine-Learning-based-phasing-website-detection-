"""Train, compare and evaluate the URL phishing models.

Data: ealvaradob/phishing-dataset (urls.json, ~836k URLs) for train/validation/test, and
pirocheto/phishing-url (11,430 URLs) as an external test set after removing every URL it shares
with the training data. (The originally planned semihGuner2002/PhishingURLsDataset is gated.)

Workflow (PRD section 8):
  load -> clean/deduplicate -> remove external overlap -> domain-grouped train/val/test split
  -> train Logistic Regression + Random Forest -> select model and risk thresholds on
  VALIDATION data -> evaluate once on the held-out TEST split -> save model + metrics.

Usage:  python scripts/train_url_model.py [--sample N]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, brier_score_loss, confusion_matrix, f1_score,
                             precision_recall_curve, precision_score, recall_score, roc_auc_score)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phishguard.url_module.features import FEATURE_NAMES  # noqa: E402
from phishguard.url_module.model import (BUNDLE_VERSION, build_logistic_regression,  # noqa: E402
                                         build_random_forest)

TRAIN_DATASET = {"id": "ealvaradob/phishing-dataset", "file": "urls.json",
                 "labels": "1 = phishing, 0 = benign (documented in dataset card)"}
EXTERNAL_DATASET = {"id": "pirocheto/phishing-url", "files": ["data/train.parquet", "data/test.parquet"],
                    "labels": "status column: 'phishing' / 'legitimate'"}
SEED = 42
_SCHEME = r"^[a-zA-Z][a-zA-Z0-9+.-]*://"
_SLD = {"co", "com", "net", "org", "gov", "ac", "edu", "or", "ne", "go"}


def _fetch(repo: str, filename: str) -> Path:
    from huggingface_hub import hf_hub_download
    return Path(hf_hub_download(repo_id=repo, filename=filename, repo_type="dataset"))


def norm_key(s: pd.Series) -> pd.Series:
    """Normalised form used for de-duplication / overlap checks (scheme, www, trailing / removed)."""
    return (s.str.strip().str.lower().str.replace(_SCHEME, "", regex=True)
            .str.replace(r"^www\.", "", regex=True).str.rstrip("/"))


def domain_group(key: pd.Series) -> pd.Series:
    """Approximate registrable domain, used so no domain appears in both train and test."""
    host = key.str.split(r"[/?#:]", n=1, regex=True).str[0]

    def reg(h: str) -> str:
        parts = [p for p in h.split(".") if p]
        if len(parts) >= 3 and parts[-2] in _SLD and len(parts[-1]) == 2:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return host.map(reg)


def clean(df: pd.DataFrame, stats: dict, prefix: str) -> pd.DataFrame:
    stats[f"{prefix}_raw_rows"] = len(df)
    df = df.dropna(subset=["url", "y"]).copy()
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"].str.len().between(4, 2048)]
    df["key"] = norm_key(df["url"])
    conflict = df.groupby("key")["y"].nunique()
    bad = set(conflict[conflict > 1].index)
    stats[f"{prefix}_conflicting_label_urls_dropped"] = len(bad)
    df = df[~df["key"].isin(bad)].drop_duplicates("key")
    stats[f"{prefix}_clean_rows"] = len(df)
    return df.reset_index(drop=True)


def load_data() -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    stats: dict = {}
    main = pd.read_json(_fetch(TRAIN_DATASET["id"], TRAIN_DATASET["file"]))
    main = clean(main.rename(columns={"text": "url", "label": "y"}), stats, "main")

    ext = pd.concat([pd.read_parquet(_fetch(EXTERNAL_DATASET["id"], f)) for f in EXTERNAL_DATASET["files"]])
    ext = pd.DataFrame({"url": ext["url"], "y": (ext["status"] == "phishing").astype(int)})
    ext = clean(ext, stats, "external")

    # The external set was largely folded into the main compilation; remove those URLs from the
    # main data so the external evaluation is on URLs the model has never seen.
    overlap = set(main["key"]) & set(ext["key"])
    stats["main_rows_removed_overlap_with_external"] = len(overlap)
    main = main[~main["key"].isin(overlap)].reset_index(drop=True)
    main["group"] = domain_group(main["key"])
    return main, ext, stats


def metrics(y, p, threshold) -> dict:
    pred = (p >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "threshold": round(float(threshold), 4),
        "accuracy": round(accuracy_score(y, pred), 4),
        "precision": round(precision_score(y, pred, zero_division=0), 4),
        "recall": round(recall_score(y, pred, zero_division=0), 4),
        "f1": round(f1_score(y, pred, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y, p), 4),
        "brier_score": round(brier_score_loss(y, p), 4),
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else None,
        "false_negative_rate": round(fn / (fn + tp), 4) if fn + tp else None,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "n": int(len(y)),
    }


def choose_risk_thresholds(y, p, target=0.95) -> dict:
    """HIGH: smallest score whose precision (share actually phishing) >= target.
    LOW: largest score below which the phishing rate is <= 1 - target.
    Chosen on validation data and reported again on the test set."""
    prec, _, thr = precision_recall_curve(y, p)
    ok = np.where(prec[:-1] >= target)[0]
    high = float(thr[ok[0]]) if len(ok) else 0.9
    order = np.argsort(p)
    ps, ys = p[order], y[order]
    cum_rate = np.cumsum(ys) / np.arange(1, len(ys) + 1)
    good = np.where(cum_rate <= 1 - target)[0]
    low = float(ps[good[-1]]) if len(good) else 0.1
    low = min(low, high)
    return {"low": round(low, 4), "high": round(high, 4), "target_band_purity": target}


def band_report(y, p, th) -> dict:
    bands = {"LOW RISK": p < th["low"], "MEDIUM RISK": (p >= th["low"]) & (p < th["high"]),
             "HIGH RISK": p >= th["high"]}
    return {k: {"n": int(m.sum()), "share_of_inputs": round(float(m.mean()), 4),
                "actual_phishing_rate": round(float(y[m].mean()), 4) if m.any() else None}
            for k, m in bands.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=0, help="subsample N training rows (quick runs)")
    args = ap.parse_args()

    main_df, ext, data_stats = load_data()
    # Domain-grouped split (~80/10/10): every URL of a registrable domain lands in the same split.
    bucket = pd.util.hash_pandas_object(main_df["group"], index=False).to_numpy() % 10
    tr, va, te = main_df[bucket >= 2], main_df[bucket == 1], main_df[bucket == 0]
    if args.sample and args.sample < len(tr):
        tr = tr.sample(args.sample, random_state=SEED)
    for name, part in (("train", tr), ("validation", va), ("test", te), ("external", ext)):
        data_stats[f"{name}_rows"] = len(part)
        data_stats[f"{name}_phishing_ratio"] = round(float(part["y"].mean()), 4)
    data_stats["split"] = "domain-grouped hash split 80/10/10 (no registrable domain shared across splits)"
    print(json.dumps(data_stats, indent=2))

    Xtr, ytr = tr["url"].tolist(), tr["y"].to_numpy()
    Xva, yva = va["url"].tolist(), va["y"].to_numpy()
    Xte, yte = te["url"].tolist(), te["y"].to_numpy()
    Xex, yex = ext["url"].tolist(), ext["y"].to_numpy()

    candidates = {"logistic_regression": build_logistic_regression(),
                  "random_forest": build_random_forest()}
    results, fitted = {}, {}
    for name, pipe in candidates.items():
        t0 = time.time()
        pipe.fit(Xtr, ytr)
        fit_s = time.time() - t0
        p_va = pipe.predict_proba(Xva)[:, 1]
        # decision threshold maximising validation F1
        prec, rec, thr = precision_recall_curve(yva, p_va)
        f1s = 2 * prec[:-1] * rec[:-1] / np.clip(prec[:-1] + rec[:-1], 1e-12, None)
        dthr = float(thr[np.argmax(f1s)])
        results[name] = {"train_seconds": round(fit_s, 1), "decision_threshold": round(dthr, 4),
                         "validation": metrics(yva, p_va, dthr),
                         "validation_at_0.5": metrics(yva, p_va, 0.5)}
        fitted[name] = (pipe, p_va, dthr)
        print(name, json.dumps(results[name]["validation"]))

    best = max(results, key=lambda n: results[n]["validation"]["f1"])
    pipe, p_va, dthr = fitted[best]
    risk_th = choose_risk_thresholds(yva, p_va)

    # Single final evaluation on the untouched test split, for every model.
    for name, (m, _, t) in fitted.items():
        p_te = m.predict_proba(Xte)[:, 1]
        results[name]["test"] = metrics(yte, p_te, t)
        if name == best:
            results[name]["test_risk_bands"] = band_report(yte, p_te, risk_th)
            fp_idx = np.where((p_te >= t) & (yte == 0))[0]
            fn_idx = np.where((p_te < t) & (yte == 1))[0]
            rng = np.random.default_rng(SEED)
            results[name]["test_error_examples"] = {
                "false_positives": [{"url": Xte[i], "p": round(float(p_te[i]), 3)}
                                    for i in rng.choice(fp_idx, min(15, len(fp_idx)), replace=False)],
                "false_negatives": [{"url": Xte[i], "p": round(float(p_te[i]), 3)}
                                    for i in rng.choice(fn_idx, min(15, len(fn_idx)), replace=False)],
            }
        p_ex = m.predict_proba(Xex)[:, 1]
        results[name]["external_test"] = metrics(yex, p_ex, t)
        if name == best:
            results[name]["external_risk_bands"] = band_report(yex, p_ex, risk_th)
        print(name, "TEST", json.dumps(results[name]["test"]))
        print(name, "EXTERNAL", json.dumps(results[name]["external_test"]))

    if best == "logistic_regression":
        tfidf = pipe.named_steps["features"].transformer_list[0][1].named_steps["tfidf"]
        feature_names = ([f"char_tfidf__{n}" for n in tfidf.get_feature_names_out()]
                         + [f"handcrafted__{n}" for n in FEATURE_NAMES])
    else:
        feature_names = [f"handcrafted__{n}" for n in FEATURE_NAMES]
        imp = pipe.named_steps["clf"].feature_importances_
        results[best]["feature_importances"] = dict(sorted(
            zip(FEATURE_NAMES, map(lambda v: round(float(v), 4), imp)), key=lambda kv: -kv[1]))

    trained_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    bundle = {
        "bundle_version": BUNDLE_VERSION,
        "model": pipe,
        "model_name": best,
        "decision_threshold": round(dthr, 4),
        "risk_thresholds": risk_th,
        "feature_names": feature_names,
        "trained_at": trained_at,
        "dataset": {"train_source": TRAIN_DATASET, "external_test_source": EXTERNAL_DATASET, **data_stats},
        "test_metrics": results[best]["test"],
        "external_test_metrics": results[best]["external_test"],
    }
    (ROOT / "models").mkdir(exist_ok=True)
    (ROOT / "reports").mkdir(exist_ok=True)
    joblib.dump(bundle, ROOT / "models" / "url_model.joblib", compress=3)
    report = {"trained_at": trained_at, "selected_model": best, "selection_criterion": "validation F1",
              "risk_thresholds": risk_th, "data": bundle["dataset"], "models": results}
    (ROOT / "reports" / "url_model_metrics.json").write_text(json.dumps(report, indent=2))
    print(f"\nSelected {best}. Saved models/url_model.joblib and reports/url_model_metrics.json")


if __name__ == "__main__":
    main()
