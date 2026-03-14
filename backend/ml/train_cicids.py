"""Train IDS models from local CSV dataset files only (no MongoDB dependency)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


def _normalize_label(raw: str) -> str:
    value = str(raw).strip().replace("\ufeff", "")
    value = value.replace("\uFFFD", "-")
    value = value.replace("  ", " ")
    return value


def _read_sampled_csv(file_path: Path, max_rows: int, chunksize: int, seed: int) -> pd.DataFrame:
    rows = []
    remaining = max_rows

    for i, chunk in enumerate(pd.read_csv(file_path, chunksize=chunksize, low_memory=False)):
        chunk.columns = [c.strip() for c in chunk.columns]
        if "Label" not in chunk.columns:
            raise ValueError(f"Missing Label column in {file_path.name}")

        if max_rows > 0:
            if remaining <= 0:
                break
            if len(chunk) > remaining:
                chunk = chunk.sample(n=remaining, random_state=seed + i)
            remaining -= len(chunk)

        rows.append(chunk)

    if not rows:
        raise ValueError(f"No rows loaded from {file_path.name}")

    return pd.concat(rows, ignore_index=True)


def _load_dataset(dataset_dir: Path, max_rows_per_file: int, chunksize: int, seed: int) -> pd.DataFrame:
    files = sorted(dataset_dir.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files found in {dataset_dir}")

    frames = []
    for f in files:
        print(f"[INFO] Loading {f.name}")
        frames.append(_read_sampled_csv(f, max_rows_per_file, chunksize, seed))

    df = pd.concat(frames, ignore_index=True)
    df["Label"] = df["Label"].map(_normalize_label)
    return df


def _prepare_xy(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
    y = (df["Label"] != "BENIGN").astype(int)
    ports = pd.to_numeric(df.get("Destination Port"), errors="coerce")

    x = df.drop(columns=["Label"]).copy()
    for col in x.columns:
        x[col] = pd.to_numeric(x[col], errors="coerce")

    x = x.replace([np.inf, -np.inf], np.nan)
    x = x.dropna(axis=1, how="all")
    return x, y, ports


def _evaluate(y_true: np.ndarray, y_pred: np.ndarray, y_score: np.ndarray | None) -> Dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_micro": float(precision_score(y_true, y_pred, average="micro", zero_division=0)),
        "precision_macro": float(precision_score(y_true, y_pred, average="macro", zero_division=0)),
        "precision_weighted": float(precision_score(y_true, y_pred, average="weighted", zero_division=0)),
        "recall_micro": float(recall_score(y_true, y_pred, average="micro", zero_division=0)),
        "recall_macro": float(recall_score(y_true, y_pred, average="macro", zero_division=0)),
        "recall_weighted": float(recall_score(y_true, y_pred, average="weighted", zero_division=0)),
        "f1_micro": float(f1_score(y_true, y_pred, average="micro", zero_division=0)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "sensitivity": float(recall_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "custom_cost_5fn_1fp": int(5 * fn + fp),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
        "classification_report": classification_report(y_true, y_pred, output_dict=True, zero_division=0),
    }

    if y_score is not None and len(np.unique(y_true)) > 1:
        metrics["roc_auc"] = float(roc_auc_score(y_true, y_score))
    else:
        metrics["roc_auc"] = None

    return metrics


def _train_supervised(x_train: pd.DataFrame, y_train: pd.Series, seed: int) -> Pipeline:
    model = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            ("clf", SGDClassifier(loss="log_loss", class_weight="balanced", random_state=seed)),
        ]
    )
    model.fit(x_train, y_train)
    return model


def _train_unsupervised(x_train: pd.DataFrame, y_train: pd.Series, seed: int):
    pre = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
        ]
    )

    benign = x_train[y_train == 0]
    fit_data = benign if len(benign) > 1000 else x_train

    x_fit = pre.fit_transform(fit_data)
    contamination = float(np.clip(y_train.mean(), 0.01, 0.25))
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(x_fit)

    train_score = -model.score_samples(x_fit)
    threshold = float(np.percentile(train_score, 95))
    return pre, model, threshold


def _evaluate_port_baseline(
    x_train: pd.DataFrame,
    y_train: pd.Series,
    port_train: pd.Series,
    x_test: pd.DataFrame,
    y_test: pd.Series,
    port_test: pd.Series,
) -> Dict:
    feature_candidates = [
        "Flow Duration",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Total Fwd Packets",
        "Total Backward Packets",
    ]
    use_features = [f for f in feature_candidates if f in x_train.columns]
    if not use_features:
        return {"note": "Per-port baseline skipped: expected flow features not found."}

    train_df = pd.concat([x_train[use_features], port_train.rename("Destination Port")], axis=1)
    benign_train = train_df[y_train == 0].copy()
    benign_train = benign_train.dropna(subset=["Destination Port"])

    if benign_train.empty:
        return {"note": "Per-port baseline skipped: no benign samples with destination port."}

    stats = benign_train.groupby("Destination Port")[use_features].agg(["mean", "std"])
    global_mean = benign_train[use_features].mean()
    global_std = benign_train[use_features].std().replace(0, 1e-6).fillna(1e-6)

    scores = []
    for idx, row in x_test[use_features].iterrows():
        p = port_test.loc[idx]
        row = row.fillna(global_mean)

        if pd.notna(p) and p in stats.index:
            means = stats.loc[p].xs("mean", level=1)
            stds = stats.loc[p].xs("std", level=1).replace(0, 1e-6).fillna(1e-6)
        else:
            means = global_mean
            stds = global_std

        z = np.abs((row - means) / stds)
        scores.append(float(np.nanmax(z.values)))

    score = np.array(scores)
    y_pred = (score >= 3.0).astype(int)
    metrics = _evaluate(y_test.to_numpy(), y_pred, score)
    metrics["threshold"] = 3.0
    metrics["scope"] = "destination-port baseline"
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Train anomaly detection models from local CIC-IDS CSV files.")
    parser.add_argument("--dataset-dir", type=str, default=str(Path(__file__).resolve().parents[2] / "dataset"))
    parser.add_argument("--output-dir", type=str, default=str(Path(__file__).resolve().parents[1] / "training_artifacts"))
    parser.add_argument("--max-rows-per-file", type=int, default=120000)
    parser.add_argument("--chunksize", type=int, default=100000)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=20260314)
    args = parser.parse_args()

    dataset_dir = Path(args.dataset_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("[INFO] Training source: dataset CSV files (MongoDB not used)")
    df = _load_dataset(dataset_dir, args.max_rows_per_file, args.chunksize, args.seed)
    x, y, ports = _prepare_xy(df)

    x_train, x_test, y_train, y_test, p_train, p_test = train_test_split(
        x,
        y,
        ports,
        test_size=args.test_size,
        random_state=args.seed,
        stratify=y,
    )

    sup = _train_supervised(x_train, y_train, args.seed)
    sup_pred = sup.predict(x_test)
    sup_score = sup.predict_proba(x_test)[:, 1]
    sup_metrics = _evaluate(y_test.to_numpy(), sup_pred, sup_score)

    pre, unsup, threshold = _train_unsupervised(x_train, y_train, args.seed)
    x_test_unsup = pre.transform(x_test)
    unsup_score = -unsup.score_samples(x_test_unsup)
    unsup_pred = (unsup_score >= threshold).astype(int)
    unsup_metrics = _evaluate(y_test.to_numpy(), unsup_pred, unsup_score)
    unsup_metrics["threshold"] = threshold

    port_metrics = _evaluate_port_baseline(x_train, y_train, p_train, x_test, y_test, p_test)

    report = {
        "dataset": {
            "dataset_dir": str(dataset_dir),
            "total_rows_used": int(len(df)),
            "feature_count": int(x.shape[1]),
            "benign_count": int((y == 0).sum()),
            "anomaly_count": int((y == 1).sum()),
            "label_distribution": {k: int(v) for k, v in df["Label"].value_counts().to_dict().items()},
        },
        "model_selection": {
            "recommended_primary_metric": "f1_weighted",
            "reason": "Class imbalance exists and weighted F1 balances precision and recall across both classes.",
        },
        "supervised_binary": sup_metrics,
        "unsupervised_isolation_forest": unsup_metrics,
        "per_system_proxy": port_metrics,
    }

    joblib.dump(sup, output_dir / "supervised_binary_sgd.joblib")
    joblib.dump({"preprocessor": pre, "model": unsup, "threshold": threshold}, output_dir / "unsupervised_iforest.joblib")
    (output_dir / "metrics_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"[OK] Artifacts written to: {output_dir}")
    print("[OK] Report: metrics_report.json")


if __name__ == "__main__":
    main()
