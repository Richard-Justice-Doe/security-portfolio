"""Detect velocity, geo-impossible, and amount-spike MoMo fraud.

Rule-based checks run first and are the primary, explainable output.
An Isolation Forest is trained on the same feature matrix as a second
opinion; it never overrides a rule, it only adds `ml_anomaly=1`.
"""

from __future__ import annotations

import argparse
import math
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

# Default paths resolve against this script's folder, not the working directory.
HERE = Path(__file__).resolve().parent

# Implied ground speed above this is treated as physically impossible
# for a person holding a phone (cars, tro-tros, even domestic flights
# plus airport time cannot justify Accra -> Tamale in ten minutes).
MAX_PLAUSIBLE_KMH = 400.0
VELOCITY_WINDOW = pd.Timedelta(minutes=10)
VELOCITY_COUNT = 6
AMOUNT_Z = 4.0
AMOUNT_MIN_GHS = 3000.0


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    h = math.sin(dlat / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlon / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


def flag_velocity(df: pd.DataFrame) -> pd.Series:
    """Many outbound transfers from one wallet in a short window."""
    flags = pd.Series("", index=df.index, dtype="object")
    ordered = df.sort_values("timestamp")
    for sender, group in ordered.groupby("sender_id"):
        times = group["timestamp"].to_numpy()
        idx = group.index.to_numpy()
        left = 0
        for right in range(len(times)):
            while times[right] - times[left] > VELOCITY_WINDOW:
                left += 1
            if right - left + 1 >= VELOCITY_COUNT:
                window = idx[left : right + 1]
                for i in window:
                    flags.loc[i] = _join(flags.loc[i], "velocity")
    return flags


def flag_geo(df: pd.DataFrame) -> pd.Series:
    """Same sender, two locations, implied speed above MAX_PLAUSIBLE_KMH."""
    flags = pd.Series("", index=df.index, dtype="object")
    ordered = df.sort_values("timestamp")
    for sender, group in ordered.groupby("sender_id"):
        prev = None
        for i, row in group.iterrows():
            if prev is not None:
                hours = (row["timestamp"] - prev["timestamp"]).total_seconds() / 3600.0
                if hours > 0:
                    dist = haversine_km(
                        prev["sender_lat"], prev["sender_lon"],
                        row["sender_lat"], row["sender_lon"],
                    )
                    speed = dist / hours
                    if dist > 120 and speed > MAX_PLAUSIBLE_KMH:
                        flags.loc[i] = _join(flags.loc[i], "geo_impossible")
                        flags.loc[prev.name] = _join(flags.loc[prev.name], "geo_impossible")
            prev = row
    return flags


def flag_amount(df: pd.DataFrame) -> pd.Series:
    """Outbound amount far above that wallet's own history."""
    flags = pd.Series("", index=df.index, dtype="object")
    stats = df.groupby("sender_id")["amount_ghs"].agg(["mean", "std", "median"])
    for i, row in df.iterrows():
        st = stats.loc[row["sender_id"]]
        std = st["std"] if pd.notna(st["std"]) and st["std"] > 0 else st["mean"] * 0.3
        z = (row["amount_ghs"] - st["mean"]) / std if std else 0
        if row["amount_ghs"] >= AMOUNT_MIN_GHS and (z >= AMOUNT_Z or row["amount_ghs"] >= 8 * max(st["median"], 1)):
            flags.loc[i] = _join(flags.loc[i], "amount_spike")
    return flags


def _join(existing: str, new: str) -> str:
    parts = [p for p in existing.split("|") if p]
    if new not in parts:
        parts.append(new)
    return "|".join(parts)


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """Numeric view used only by Isolation Forest (hour, amount, local velocity)."""
    feat = pd.DataFrame(index=df.index)
    feat["log_amount"] = np.log1p(df["amount_ghs"])
    feat["hour"] = df["timestamp"].dt.hour
    feat["is_night"] = feat["hour"].isin(range(0, 5)).astype(int)
    counts = (
        df.sort_values("timestamp")
        .groupby("sender_id")["txn_id"]
        .transform("count")
    )
    feat["sender_volume"] = counts
    feat["type_code"] = pd.Categorical(df["transaction_type"]).codes
    return feat.fillna(0)


def run_isolation_forest(df: pd.DataFrame, contamination: float = 0.04) -> pd.Series:
    feat = build_features(df)
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=7,
    )
    pred = model.fit_predict(feat)
    return pd.Series((pred == -1).astype(int), index=df.index, name="ml_anomaly")


def detect(df: pd.DataFrame, use_ml: bool = True) -> pd.DataFrame:
    work = df.copy()
    work["timestamp"] = pd.to_datetime(work["timestamp"])
    v = flag_velocity(work)
    g = flag_geo(work)
    a = flag_amount(work)
    reasons = []
    for i in work.index:
        reasons.append("|".join(p for p in (v.loc[i], g.loc[i], a.loc[i]) if p))
    work["rule_flags"] = reasons
    work["flagged"] = work["rule_flags"].ne("")
    if use_ml:
        work["ml_anomaly"] = run_isolation_forest(work)
    else:
        work["ml_anomaly"] = 0
    return work


def plot_timeline(df: pd.DataFrame, path: Path) -> None:
    daily = df.copy()
    daily["day"] = daily["timestamp"].dt.floor("D")
    grouped = daily.groupby("day").agg(
        total=("txn_id", "count"),
        flagged=("flagged", "sum"),
    )
    fig, ax = plt.subplots(figsize=(10, 4.5))
    ax.plot(grouped.index, grouped["total"], label="All transactions", color="#4c78a8")
    ax.plot(grouped.index, grouped["flagged"], label="Rule-flagged", color="#e45756")
    ax.set_title("Ghana MoMo lab: flagged vs all transactions")
    ax.set_ylabel("Count")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.autofmt_xdate()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)


def console_summary(df: pd.DataFrame) -> str:
    flagged = df[df["flagged"]]
    lines = [
        f"Transactions analysed : {len(df)}",
        f"Rule-flagged          : {len(flagged)} ({100 * len(flagged) / len(df):.1f}%)",
        f"Isolation Forest hits : {int(df['ml_anomaly'].sum())}",
        "",
        "Rule breakdown (a row may have more than one flag):",
    ]
    for name in ("velocity", "geo_impossible", "amount_spike"):
        n = flagged["rule_flags"].str.contains(name, regex=False).sum()
        lines.append(f"  {name:16} {n}")
    if "injected_pattern" in df.columns:
        injected = df[df["injected_pattern"] != "none"]
        caught = injected[injected["flagged"]]
        lines.append("")
        lines.append(
            f"Injected-pattern recall (lab score, not production): "
            f"{len(caught)}/{len(injected)} "
            f"({100 * len(caught) / max(len(injected), 1):.1f}%)"
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Flag synthetic MoMo fraud patterns.")
    parser.add_argument("--input", default=str(HERE / "data/momo_transactions.csv"))
    parser.add_argument("--out-csv", default=str(HERE / "reports/flagged_transactions.csv"))
    parser.add_argument("--out-chart", default=str(HERE / "reports/flagged_over_time.png"))
    parser.add_argument("--no-ml", action="store_true", help="Skip Isolation Forest")
    args = parser.parse_args()

    df = pd.read_csv(args.input)
    scored = detect(df, use_ml=not args.no_ml)
    out_csv = Path(args.out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    export_cols = [
        "txn_id",
        "timestamp",
        "sender_id",
        "receiver_id",
        "amount_ghs",
        "sender_location",
        "receiver_location",
        "transaction_type",
        "rule_flags",
        "ml_anomaly",
        "flagged",
    ]
    if "injected_pattern" in scored.columns:
        export_cols.append("injected_pattern")
    flagged_rows = scored[scored["flagged"] | (scored["ml_anomaly"] == 1)]
    flagged_rows[export_cols].to_csv(out_csv, index=False)

    chart = Path(args.out_chart)
    plot_timeline(scored, chart)
    summary = console_summary(scored)
    print(summary)
    print(f"\nCSV   -> {out_csv} ({len(flagged_rows)} rows)")
    print(f"Chart -> {chart}")


if __name__ == "__main__":
    main()
