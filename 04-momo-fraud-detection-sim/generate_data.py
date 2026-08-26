"""Synthetic Ghana mobile-money (MoMo) transaction generator.

Produces a CSV of P2P, merchant, cash-in/out, and bank-to-wallet
transfers across a GhIPSS-style interoperable wallet network. Fraud
patterns are injected with a `injected_pattern` label so the detector
can be scored later; the detector itself does *not* read that column.
"""

from __future__ import annotations

import argparse
import math
import random
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

CITIES: dict[str, tuple[float, float]] = {
    "Accra": (5.6037, -0.1870),
    "Kumasi": (6.6885, -1.6244),
    "Tamale": (9.4034, -0.8424),
    "Takoradi": (4.9016, -1.7831),
    "Cape Coast": (5.1053, -1.2466),
    "Ho": (6.6008, 0.4713),
    "Bolgatanga": (10.7856, -0.8514),
    "Wa": (10.0601, -2.5099),
    "Koforidua": (6.0941, -0.2591),
    "Sunyani": (7.3399, -2.3268),
}

PROVIDERS = ("MTN", "Telecel", "AirtelTigo")
TX_TYPES = (
    "p2p",
    "merchant",
    "cash_in",
    "cash_out",
    "bank_to_wallet",
)

# Home cities are sticky: most of an account's traffic stays in one metro.
HOME_WEIGHTS = {
    "Accra": 0.38,
    "Kumasi": 0.18,
    "Tamale": 0.08,
    "Takoradi": 0.07,
    "Cape Coast": 0.06,
    "Ho": 0.05,
    "Koforidua": 0.06,
    "Sunyani": 0.05,
    "Bolgatanga": 0.04,
    "Wa": 0.03,
}


def _pick_city(rng: random.Random, home: str) -> str:
    if rng.random() < 0.82:
        return home
    others = [c for c in CITIES if c != home]
    return rng.choice(others)


def _haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    r = 6371.0
    lat1, lon1 = math.radians(a[0]), math.radians(a[1])
    lat2, lon2 = math.radians(b[0]), math.radians(b[1])
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


def _snap_to_plausible_city(
    account_id: str,
    proposed: str,
    ts: datetime,
    last_seen: dict[str, tuple[datetime, str]],
) -> str:
    """Keep ordinary traffic on a physically possible itinerary (~90 km/h)."""
    if account_id not in last_seen:
        return proposed
    prev_ts, prev_city = last_seen[account_id]
    hours = max((ts - prev_ts).total_seconds() / 3600.0, 0.0)
    need = _haversine_km(CITIES[prev_city], CITIES[proposed]) / 90.0
    return proposed if hours >= need else prev_city


def _wallet_id(provider: str, n: int) -> str:
    return f"{provider[:3].upper()}-{n:05d}"


def _amount(rng: random.Random, tx_type: str) -> float:
    # Typical MoMo ticket sizes in GHS (synthetic, not from any operator dump).
    if tx_type == "cash_in":
        return round(rng.lognormvariate(4.2, 0.6), 2)  # ~GHS 70 median-ish
    if tx_type == "cash_out":
        return round(rng.lognormvariate(4.0, 0.7), 2)
    if tx_type == "merchant":
        return round(rng.lognormvariate(3.4, 0.8), 2)
    if tx_type == "bank_to_wallet":
        return round(rng.lognormvariate(5.0, 0.5), 2)
    return round(rng.lognormvariate(3.8, 0.7), 2)


def generate(n_accounts: int = 80, n_normal: int = 2800, seed: int = 7) -> pd.DataFrame:
    rng = random.Random(seed)
    start = datetime(2026, 8, 1, 6, 0, 0)
    horizon_hours = 14 * 24

    homes = rng.choices(list(HOME_WEIGHTS), weights=list(HOME_WEIGHTS.values()), k=n_accounts)
    accounts = []
    for i in range(n_accounts):
        provider = PROVIDERS[i % len(PROVIDERS)]
        accounts.append(
            {
                "account_id": _wallet_id(provider, i + 1),
                "provider": provider,
                "home": homes[i],
            }
        )

    rows: list[dict] = []

    def add_tx(
        sender,
        receiver_id: str,
        receiver_city: str,
        ts: datetime,
        amount: float,
        tx_type: str,
        pattern: str,
    ) -> None:
        s_lat, s_lon = CITIES[sender["city"]]
        r_lat, r_lon = CITIES[receiver_city]
        rows.append(
            {
                "txn_id": f"TXN-{len(rows) + 1:06d}",
                "timestamp": ts.isoformat(sep=" ", timespec="seconds"),
                "sender_id": sender["account_id"],
                "receiver_id": receiver_id,
                "amount_ghs": round(amount, 2),
                "sender_location": sender["city"],
                "receiver_location": receiver_city,
                "sender_lat": s_lat,
                "sender_lon": s_lon,
                "receiver_lat": r_lat,
                "receiver_lon": r_lon,
                "transaction_type": tx_type,
                "sender_provider": sender["provider"],
                "injected_pattern": pattern,
            }
        )

    # --- Normal traffic (cities snapped so a wallet cannot teleport) ---
    drafts: list[tuple] = []
    for _ in range(n_normal):
        sender_meta = rng.choice(accounts)
        recv_meta = rng.choice(accounts)
        while recv_meta["account_id"] == sender_meta["account_id"]:
            recv_meta = rng.choice(accounts)
        tx_type = rng.choices(TX_TYPES, weights=(0.45, 0.25, 0.12, 0.10, 0.08))[0]
        ts = start + timedelta(hours=rng.uniform(0, horizon_hours), seconds=rng.randint(0, 59))
        drafts.append((ts, sender_meta, recv_meta, tx_type, _amount(rng, tx_type)))

    drafts.sort(key=lambda row: row[0])
    last_seen: dict[str, tuple[datetime, str]] = {}
    for ts, sender_meta, recv_meta, tx_type, amount in drafts:
        proposed = _pick_city(rng, sender_meta["home"])
        city = _snap_to_plausible_city(sender_meta["account_id"], proposed, ts, last_seen)
        sender = {**sender_meta, "city": city}
        if tx_type == "merchant":
            receiver_id = f"MERCH-{rng.randint(1, 40):03d}"
            recv_city = city
        else:
            receiver_id = recv_meta["account_id"]
            recv_city = _pick_city(rng, recv_meta["home"])
        add_tx(sender, receiver_id, recv_city, ts, amount, tx_type, "none")
        last_seen[sender_meta["account_id"]] = (ts, city)

    # --- Velocity: one wallet fires many P2P sends in a few minutes (SIM-box / mule). ---
    for burst_i in range(8):
        mule = rng.choice(accounts)
        city = mule["home"]
        t0 = start + timedelta(hours=rng.uniform(12, horizon_hours - 12))
        for j in range(rng.randint(8, 14)):
            victim = rng.choice(accounts)
            sender = {**mule, "city": city}
            add_tx(
                sender,
                victim["account_id"],
                victim["home"],
                t0 + timedelta(seconds=j * rng.randint(20, 45)),
                round(rng.uniform(80, 250), 2),
                "p2p",
                "velocity",
            )

    # --- Geo-impossible: same sender, distant cities, minutes apart. ---
    far_pairs = [("Accra", "Tamale"), ("Accra", "Wa"), ("Kumasi", "Bolgatanga"), ("Takoradi", "Tamale")]
    for _ in range(12):
        acc = rng.choice(accounts)
        a, b = rng.choice(far_pairs)
        t0 = start + timedelta(hours=rng.uniform(24, horizon_hours - 24))
        recv = rng.choice(accounts)
        add_tx({**acc, "city": a}, recv["account_id"], recv["home"], t0, _amount(rng, "p2p"), "p2p", "geo_impossible")
        add_tx(
            {**acc, "city": b},
            rng.choice(accounts)["account_id"],
            b,
            t0 + timedelta(minutes=rng.randint(4, 12)),
            _amount(rng, "p2p"),
            "p2p",
            "geo_impossible",
        )

    # --- Amount spike: quiet wallet suddenly sends a payroll-sized transfer. ---
    quiet = rng.sample(accounts, 15)
    for acc in quiet:
        t0 = start + timedelta(hours=rng.uniform(48, horizon_hours - 6))
        recv = rng.choice(accounts)
        add_tx(
            {**acc, "city": acc["home"]},
            recv["account_id"],
            recv["home"],
            t0,
            round(rng.uniform(8000, 18000), 2),
            "p2p",
            "amount_spike",
        )

    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    df["txn_id"] = [f"TXN-{i:06d}" for i in range(1, len(df) + 1)]
    return df


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a synthetic Ghana MoMo transaction CSV.")
    parser.add_argument("--out", default="data/momo_transactions.csv")
    parser.add_argument("--accounts", type=int, default=80)
    parser.add_argument("--normal", type=int, default=2800)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    df = generate(n_accounts=args.accounts, n_normal=args.normal, seed=args.seed)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)
    counts = df["injected_pattern"].value_counts().to_dict()
    print(f"Wrote {len(df)} transactions -> {out}")
    print("injected_pattern counts:", counts)


if __name__ == "__main__":
    main()
