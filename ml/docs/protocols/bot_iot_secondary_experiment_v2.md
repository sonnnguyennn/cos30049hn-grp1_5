# Bot-IoT secondary v2 — PREPARED_PENDING_REVIEW

Preparation authorized after structural TEST diagnostics at c8d1de7, before any model
fitting or performance assessment. This revision is not a pristine design-blind TEST
protocol. All v1 contracts, receipts and evidence remain historical and unchanged.
Authority: `artifacts/contracts/bot_iot_secondary_ml_v2.json` and decision record
`docs/decisions/BOT_IOT_V2_PREPARATION.md`. Commit these before fitting preprocessing.

Keep the same13 predictors, seed1729, source observations, labels and exact-X groups.
Reuse existing source-order membership JSONLs with identical hashes. TRAIN2,201,114
(286 benign), VALIDATION733,704 (96 benign), TEST733,704 (95 benign). No resampling,
regrouping or seed changes. Mixed group11 benign/3,733 malicious stays intact in TRAIN;
accept its representational ambiguity without asserting annotation error.

Fit StandardScaler on every TRAIN observation only (population variance ddof0), in
bounded source-order batches. Persist exact sample count, mean, variance and scale.
Learn category vocabularies from TRAIN alone: exact valid strings, sorted Unicode order.
Keep case/internal spaces. Empty, outer-whitespace and nan/null/none tokens remain invalid.
Append a separate typed UNKNOWN slot for each field; valid unseen strings map generically
to it. This is not a magic source string. Known values remain source-tagged even if their
text resembles UNKNOWN. Never add particular VALIDATION/TEST values to vocabulary.

No one-hot category is dropped. Encoded order:10 numeric fields then flgs known9+UNKNOWN,
proto known4+UNKNOWN, state known10+UNKNOWN =36 features. Persist vocabulary and actual
encoded names/order. VALIDATION has no unknown;8 TEST observations use UNKNOWN for proto
and state. These are mechanical checks, not performance metrics. Invalid input still fails.

Builder emits a fresh external package with NumPy-only portable loader, standalone verifier,
README, preprocessing state, raw numeric/category-code arrays, labels, lineage, group
dictionary, membership files and checksums. No manual package edits. Default TEST access
must fail; verifier uses explicit mechanical access. No raw dataset or IoTGuard checkout
is needed to load or verify a relocated package. Verify original source/evidence hashes
before reuse; do not rerun G1/G2 or alter their outputs.

Manifest binds v2 contract/protocol/decision hashes, source revision and dirty status,
implementation hashes, inherited evidence, exact memberships, preprocessor hash and all
payload hashes. Persist build/reload/portable parity results. Status is
PREPARED_PENDING_REVIEW, never READY_FOR_TRAINING or TEAM_VERIFIED by this checkpoint.

Primary reporting uses observation weight1 and integer confusion counts, both class
supports/recalls, malicious precision, FPR and macro-F1. Accuracy is supplementary.
For group sensitivity each observation has weight1/n_g for its original exact-X group
within that partition, including mixed-label groups. Each group has total mass1; weights
are neither label-conditional nor class-balanced. Report weighted confusion masses,
weighted supports/recalls, FPR and macro-F1 separately from integer counts.
Model/hyperparameter/threshold selection uses VALIDATION only; TEST metrics are not computed
here. All classifier/clustering fitting, including smoke, occurs on Kaggle.

Report small benign support96/95 and group concentration: the largest benign group is
18/96 VALIDATION and8/95 TEST. Use group-aware uncertainty; repeated observations do not
create independent evidence. Scope remains this within-corpus5% capture; no unseen-device,
future-time, N-BaIoT transfer or deployment claim. PM/Hiếu review and Kaggle runtime/training
validation remain outstanding after mechanical package verification.
