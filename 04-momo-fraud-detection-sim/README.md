# Mobile Money (MoMo) Fraud Detection Simulator

A **synthetic** Ghana mobile-money lab: generate a two-week slice of interoperable wallet traffic, inject three fraud patterns that show up on GhIPSS-style rails, then flag them with explainable rules plus an optional Isolation Forest.

No operator data is used. Wallet IDs, amounts, and cities are made up.

## Problem it solves

Ghana's MoMo market (MTN, Telecel, AirtelTigo) settles across operators through **GhIPSS** (Ghana Interbank Payment and Settlement Systems) interoperability. Fraud follows the rails: a compromised SIM can spray P2P transfers in minutes, a stolen profile can "travel" Accra to Tamale faster than any vehicle, and a quiet wallet can suddenly move a payroll-sized amount. This project is a detector you can read, not a black-box vendor demo.

## Fraud patterns modelled

| Pattern | Story | Detector |
| --- | --- | --- |
| **Velocity** | One wallet sends ≥6 transfers in 10 minutes (mule / SIM-box style burst) | Sliding window per `sender_id` |
| **Geo-impossible** | Same wallet presents in two cities whose implied speed exceeds 400 km/h | Haversine distance / time between consecutive sends |
| **Amount spike** | Transfer ≥ GHS 3,000 and ≥ 4σ (or 8× median) above that wallet's own history | Per-account z-score + median multiple |

Isolation Forest is a second opinion on `(log amount, hour, night flag, sender volume, type)`. It does not override the rules; the CSV records `ml_anomaly=1` separately so you can see agreement.

## Setup

Python 3.10+. From this directory:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python generate_data.py --out data/momo_transactions.csv
python detect_fraud.py --input data/momo_transactions.csv
```

Outputs:

- `reports/flagged_transactions.csv` — every rule- or ML-flagged row with a reason
- `reports/flagged_over_time.png` — daily volume vs flagged count
- console summary (counts and injected-pattern recall)

Skip the model with `--no-ml` if you only want the rules.

## Example output

```
Transactions analysed : 2938
Rule-flagged          : 140 (4.8%)
Isolation Forest hits : 118

Rule breakdown (a row may have more than one flag):
  velocity         99
  geo_impossible   28
  amount_spike     15

Injected-pattern recall (lab score, not production): 138/138 (100.0%)

CSV   -> reports/flagged_transactions.csv
Chart -> reports/flagged_over_time.png
```

(Exact counts depend on `--seed`; the bundled generator defaults to seed 7.)

CSV columns include `rule_flags` (`velocity`, `geo_impossible`, `amount_spike`, possibly combined with `|`) and `ml_anomaly`. `injected_pattern` is a **lab-only** label the detector does not read; it is written so you can score the exercise.

## Ghana / GhIPSS framing

- **Interoperability:** a sender on MTN can pay a Telecel wallet. The generator mixes `MTN-`, `TEL-`, and `AIR-` prefixes and merchant IDs (`MERCH-00n`) to stand in for that mesh. It does not implement GhIPSS message formats.
- **Locations:** Accra, Kumasi, Tamale, Takoradi, Cape Coast, Ho, Koforidua, Sunyani, Bolgatanga, Wa — with approximate coordinates so geo-speed is computable.
- **Transaction types:** `p2p`, `merchant`, `cash_in`, `cash_out`, `bank_to_wallet`.

## Ethical use

- Synthetic data only. Do not load real customer ledgers into this folder.
- This is not an accusation engine for live wallets and has no legal or SAR-filing standing.
- Recall against injected labels is a teaching metric; production fraud systems need labelled operator data, device signals, and human review.

## Limitations

Rules fire on the patterns they were written for; a patient mule who stays under six transfers per ten minutes will slip through. Isolation Forest contamination is a knob (`0.04`), not a learned fraud rate. There is no graph (circular mule rings) or SIM-swap signal in this version.
