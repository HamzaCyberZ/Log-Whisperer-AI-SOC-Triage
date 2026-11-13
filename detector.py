# detector.py
"""
Anomaly detection layer.

Two complementary detectors are combined:
  1. Isolation Forest on TF-IDF features (catches statistical outliers)
  2. Signature rules (catches known attack patterns regardless of frequency)

Union of both = more robust than either alone.
"""
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest

from utils.log_parser import (
    normalize_line,
    split_logs,
    signature_matches,
    extract_ips,
    extract_timestamp,
    extract_status_code,
    extract_path,
)


def _isolation_forest_pass(normed_lines: list[str], contamination: float):
    """Run TF-IDF + Isolation Forest, return predictions and scores."""
    vectorizer = TfidfVectorizer(max_features=1500, ngram_range=(1, 2))
    X = vectorizer.fit_transform(normed_lines)

    model = IsolationForest(
        n_estimators=150,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    preds = model.fit_predict(X.toarray()) # type: ignore
    scores = model.decision_function(X.toarray()) # type: ignore
    return preds, scores


def detect_anomalies(raw_logs: str, contamination: float = 0.15) -> pd.DataFrame:
    """
    Analyze raw logs and return an enriched DataFrame.

    Columns:
        line        : original log line
        anomaly     : 1 = suspicious, 0 = normal
        score       : Isolation Forest decision score (lower = more anomalous)
        signatures  : comma-joined attack signature names
        ips         : comma-joined IPs in the line
        timestamp   : best-effort timestamp
        status      : HTTP status code (if any)
        path        : URL path (if any)
        reason      : short human-readable reason for the flag
    """
    lines = split_logs(raw_logs)

    empty_cols = ['line', 'anomaly', 'score', 'signatures',
                  'ips', 'timestamp', 'status', 'path', 'reason']

    if len(lines) < 10:
        df = pd.DataFrame({c: [] for c in empty_cols})
        for l in lines:
            df.loc[len(df)] = [l, 0, 0.0, '', '', '', '', '', '']
        return df

    normed = [normalize_line(l) for l in lines]
    preds, scores = _isolation_forest_pass(normed, contamination)

    rows = []
    for i, line in enumerate(lines):
        sigs = signature_matches(line)
        is_anomaly_if = preds[i] == -1
        is_anomaly = is_anomaly_if or len(sigs) > 0

        reasons = []
        if is_anomaly_if:
            reasons.append("statistical outlier")
        if sigs:
            reasons.append("matched signature: " + ", ".join(sigs))

        rows.append({
            'line': line,
            'anomaly': 1 if is_anomaly else 0,
            'score': float(scores[i]),
            'signatures': ", ".join(sigs),
            'ips': ", ".join(extract_ips(line)),
            'timestamp': extract_timestamp(line),
            'status': extract_status_code(line),
            'path': extract_path(line),
            'reason': " | ".join(reasons) if reasons else "",
        })

    df = pd.DataFrame(rows)
    # Sort: anomalous first, then by score ascending (most anomalous first)
    df = df.sort_values(['anomaly', 'score'],
                        ascending=[False, True]).reset_index(drop=True)
    return df


def summarize(df: pd.DataFrame) -> dict:
    """Aggregate stats used by the UI header and the LLM prompt."""
    anomalies = df[df['anomaly'] == 1]

    all_sigs = []
    for s in anomalies['signatures']:
        if s:
            all_sigs.extend([x.strip() for x in s.split(',')])

    sig_counts = {}
    for s in all_sigs:
        sig_counts[s] = sig_counts.get(s, 0) + 1

    ips = []
    for ip_str in anomalies['ips']:
        if ip_str:
            ips.extend([x.strip() for x in ip_str.split(',')])

    unique_ips = sorted(set(ips))

    return {
        'total': len(df),
        'anomalies': len(anomalies),
        'top_signatures': sorted(sig_counts.items(),
                                 key=lambda kv: -kv[1])[:5],
        'involved_ips': unique_ips[:10],
    }