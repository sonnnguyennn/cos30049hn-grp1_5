# Dataset label and taxonomy evidence (A3)

This document records the A3 label audit. It is an engineering evidence note, not a
dataset-role decision and not an ML preprocessing specification. All source and externally
extracted files remained read-only.

## Evidence boundary

The audit uses `artifacts/audit/n_baiot_csv_structure.csv` for N-BaIoT provenance and exact
row counts. It streams only `attack`, `category`, and `subcategory` from the seven local
Bot-IoT CSV files. It does not profile general missing values, remove duplicates, inspect
candidate leakage fields, balance classes, choose a representation, or train a model.

## N-BaIoT

### Source facts

- The 115-column N-BaIoT schema has no explicit label column.
- Class identity is carried by source provenance: device, source kind, archive family,
  parent archive, member/source filename, and logical ID.
- Member filename alone is not globally unique. Both Gafgyt and Mirai contain `scan.csv`
  and `udp.csv`.
- The verified A2 evidence contains 89 logical CSVs and 7,062,606 rows.
- `Ennio_Doorbell` and `Samsung_SNH_1011_N_Webcam` have no observed Mirai archive. This is
  recorded coverage, not evidence of corruption.

### IoTGuard project convention

IoTGuard adds, but never substitutes for, raw provenance:

- binary: `benign`, `malicious`;
- family: `benign`, `gafgyt`, `mirai`;
- fine class: `benign`, or the exact archive family plus member stem, such as
  `gafgyt_scan` and `mirai_scan`.

The mapping is strict and versioned by the A3 script and evidence hashes. An unexpected
source kind, archive family, parent archive, or member name is an error; there is no silent
`UNKNOWN` fallback.

### Exact distributions

| Level | Label | Rows | Percent of 7,062,606 |
|---|---|---:|---:|
| binary | benign | 555,932 | 7.871485397882878% |
| binary | malicious | 6,506,674 | 92.128514602117122% |
| family | benign | 555,932 | 7.871485397882878% |
| family | gafgyt | 2,838,272 | 40.187318958469437% |
| family | mirai | 3,668,402 | 51.941195643647685% |
| fine | benign | 555,932 | 7.871485397882878% |
| fine | gafgyt_combo | 515,156 | 7.294134771216177% |
| fine | gafgyt_junk | 261,789 | 3.706691269483247% |
| fine | gafgyt_scan | 255,111 | 3.612136936422618% |
| fine | gafgyt_tcp | 859,850 | 12.174684528628668% |
| fine | gafgyt_udp | 946,366 | 13.399671452718727% |
| fine | mirai_ack | 643,821 | 9.115912738159257% |
| fine | mirai_scan | 537,979 | 7.617287443190233% |
| fine | mirai_syn | 733,299 | 10.382838855799120% |
| fine | mirai_udp | 1,229,999 | 17.415653655322129% |
| fine | mirai_udpplain | 523,304 | 7.409502951176945% |

Exact full-precision percentages and every device-by-label distribution are retained in the
CSV evidence rather than rounded for computation.

## Bot-IoT

### Source facts from the local All-features 5% shards

The All-features representation has 46 observed columns. That phrase does not mean 46
usable ML features. `attack`, `category`, and `subcategory` are label/target metadata and
must not be candidate predictors.

No null, empty, outer-whitespace, case-only variant, or malformed label value was observed
in 3,668,522 rows.

| Field | Exact raw value | Rows |
|---|---|---:|
| attack | `0` | 477 |
| attack | `1` | 3,668,045 |
| category | `DDoS` | 1,926,624 |
| category | `DoS` | 1,650,260 |
| category | `Normal` | 477 |
| category | `Reconnaissance` | 91,082 |
| category | `Theft` | 79 |
| subcategory | `Data_Exfiltration` | 6 |
| subcategory | `HTTP` | 2,474 |
| subcategory | `Keylogging` | 73 |
| subcategory | `Normal` | 477 |
| subcategory | `OS_Fingerprint` | 17,914 |
| subcategory | `Service_Scan` | 73,168 |
| subcategory | `TCP` | 1,593,180 |
| subcategory | `UDP` | 1,981,230 |

The `attack` values are exact CSV strings whose lexical type is `integer_string`; the other
label values are exact text strings.

### Proven relationships

- Every observed `attack=0` row is exactly `category=Normal, subcategory=Normal` (477 rows).
- Every observed `attack=1` row has a non-`Normal` category and subcategory (3,668,045 rows).
- Category determines attack in this local subset: `Normal` maps to `0`; `DDoS`, `DoS`,
  `Reconnaissance`, and `Theft` map to `1`.
- Subcategory also determines attack in this local subset: `Normal` maps to `0`; every other
  observed subcategory maps to `1`.
- `HTTP`, `TCP`, and `UDP` each occur under both `DDoS` and `DoS`; therefore subcategory does
  not uniquely determine category.
- `OS_Fingerprint` and `Service_Scan` occur under `Reconnaissance`.
- `Data_Exfiltration` and `Keylogging` occur under `Theft`.
- No observed category/subcategory pair conflicts with the proven attack semantics.

The exact 11 observed `(attack, category, subcategory)` combinations and their counts are in
`bot_iot_label_distribution.csv`.

### IoTGuard project convention

Raw fields are preserved as `raw_attack`, `raw_category`, and `raw_subcategory`. IoTGuard
adds these canonical fields:

- `attack`: `0 -> benign`, `1 -> malicious`;
- categories: `DDoS -> ddos`, `DoS -> dos`, `Normal -> normal`,
  `Reconnaissance -> reconnaissance`, `Theft -> theft`;
- subcategories: spelling/case normalization to `data_exfiltration`, `http`, `keylogging`,
  `normal`, `os_fingerprint`, `service_scan`, `tcp`, and `udp`.

These mappings are one-to-one over observed raw values. They do not merge semantically
different source labels. The exact machine-readable mapping is in
`bot_iot_canonical_label_mapping.csv`.

## Representation comparison

Independent profiles were built for All-features, 10-best full, predefined train, and
predefined test. The following all match exactly at aggregate level:

- total rows;
- raw `attack` distribution;
- raw `category` distribution;
- raw `subcategory` distribution;
- joint `(attack, category, subcategory)` distribution.

All-features and 10-best full each contain 3,668,522 rows. Predefined train has 2,934,817
rows, predefined test has 733,705 rows, and their aggregate label distributions reproduce
10-best full.

This proves only that aggregate label distributions match. It does not prove that the
representations contain exactly the same records, preserve row order, or have record-level
lineage. No Bot-IoT representation is selected for ML by A3.

## Evidence and verification

Primary evidence is generated by `scripts/dataset_label_audit.py` with Python's streaming
CSV reader. `scripts/verify_a3_evidence.py` independently recomputes Bot-IoT label counts
with pandas chunked reads and independently maps N-BaIoT provenance. Verification also
reconciles all source paths, sizes, and raw-source timestamps with A1 manifests; the
external extraction workspace is reconciled by path and size because its manifest does not
store timestamps.

`artifacts/audit/label_audit_summary.json` and
`artifacts/audit/a3_evidence_verification.json` contain PASS status and SHA-256 evidence.

## Deferred questions for A4/A5

A4 may inspect general missing/invalid values and duplicate records. A5 may inspect class
imbalance and leakage risks, including identifier/address/time/sequence fields. Those later
phases must decide neither record identity nor representation suitability from A3's
aggregate equality alone.
