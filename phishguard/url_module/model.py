"""Model construction, persistence and prediction for the URL module."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from .features import FEATURE_NAMES, HandcraftedFeatures, describe_indicators, normalize_for_tfidf
from .validation import validate_url

BUNDLE_VERSION = 1


def _normalize_many(X):
    return [normalize_for_tfidf(u) for u in X]


def build_logistic_regression(max_features: int = 200_000, C: float = 4.0) -> Pipeline:
    tfidf = Pipeline([
        ("normalize", FunctionTransformer(_normalize_many)),
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=3,
                                  max_features=max_features, sublinear_tf=True, dtype=np.float32)),
    ])
    handcrafted = Pipeline([("extract", HandcraftedFeatures()), ("scale", StandardScaler())])
    features = FeatureUnion([("char_tfidf", tfidf), ("handcrafted", handcrafted)])
    clf = LogisticRegression(C=C, solver="liblinear", max_iter=1000)
    return Pipeline([("features", features), ("clf", clf)])


def build_random_forest(n_estimators: int = 100, random_state: int = 42) -> Pipeline:
    # RF uses the hand-crafted features only: trees on 200k sparse TF-IDF columns
    # are slow and memory-hungry, and this gives a genuinely different baseline.
    clf = RandomForestClassifier(n_estimators=n_estimators, min_samples_leaf=10, max_features="sqrt",
                                 n_jobs=-1, random_state=random_state, class_weight=None)
    return Pipeline([("extract", HandcraftedFeatures()), ("clf", clf)])


def risk_category(p: float, thresholds: dict) -> str:
    if p >= thresholds["high"]:
        return "HIGH RISK"
    if p >= thresholds["low"]:
        return "MEDIUM RISK"
    return "LOW RISK"


@dataclass
class URLDetector:
    bundle: dict

    @classmethod
    def load(cls, path: str | Path) -> "URLDetector":
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(
                f"Model file not found at {path}. Train it first: python scripts/train_url_model.py")
        bundle = joblib.load(path)
        if bundle.get("bundle_version") != BUNDLE_VERSION:
            raise ValueError("Model bundle version mismatch; retrain the model.")
        return cls(bundle)

    @property
    def pipeline(self) -> Pipeline:
        return self.bundle["model"]

    def info(self) -> dict:
        # feature_names holds ~200k n-grams; keep it out of API responses
        return {k: v for k, v in self.bundle.items() if k not in ("model", "feature_names")}

    def _model_reasons(self, url: str, top_k: int = 6) -> list[dict]:
        """Per-input explanation from the linear model: the features with the largest
        coefficient x value contributions. Only available for Logistic Regression."""
        pipe = self.pipeline
        clf = pipe.named_steps["clf"]
        if not isinstance(clf, LogisticRegression):
            return []
        x = pipe.named_steps["features"].transform([url]).tocsr()
        coef = clf.coef_[0]
        idx = x.indices
        contrib = x.data * coef[idx]
        names = self.bundle["feature_names"]
        order = np.argsort(-np.abs(contrib))[:top_k]
        out = []
        for i in order:
            name = names[idx[i]]
            kind, _, feat = name.partition("__")
            label = f"character pattern '{feat}'" if kind == "char_tfidf" else feat.replace("_", " ")
            out.append({
                "feature": label,
                "contribution": round(float(contrib[i]), 4),
                "direction": "towards phishing" if contrib[i] > 0 else "towards legitimate",
            })
        return out

    def predict(self, url: str) -> dict:
        v = validate_url(url)  # raises URLValidationError
        p = float(self.pipeline.predict_proba([v.raw])[0, 1])
        thresholds = self.bundle["risk_thresholds"]
        return {
            "module": "url_detection",
            "input": v.raw,
            "prediction": "phishing" if p >= self.bundle["decision_threshold"] else "legitimate",
            "phishing_probability": round(p, 4),
            "risk_category": risk_category(p, thresholds),
            "indicators": describe_indicators(v.raw, v.had_scheme, v.scheme),
            "model_reasons": self._model_reasons(v.raw),
            "model": self.bundle["model_name"],
            "note": "Lexical analysis of the URL text only; the website was not visited.",
        }
