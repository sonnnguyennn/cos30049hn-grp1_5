# Bot-IoT secondary experiment v1 — PROPOSED_FOR_REVIEW

## Pre-scan policy addendum — candidate_validation_v2_pre_scan

The 13 predictors and seed1729 remain unchanged. The candidate JSON `scan_policy`
freezes exact tuple serialization, category validity/unseen handling, group allocation,
tie rules, conflict handling, gate checks and membership serialization before diagnostics.
No vocabulary, scaler or model is fitted in the targeted full scan.

Equality is the exact ordered normalized tuple (stored as a UNIQUE SQLite BLOB), not its
hash and never `(X,label)`. Numeric values are parsed binary64, signed zero becomes +0.0;
counts are also checked as exact Decimal integers <=2**53. Text remains exact Unicode,
including case/internal spaces. Compact ensure_ascii JSON of the 13 values, ASCII bytes,
no newline is the canonical serialization. SHA256 is a compact identifier and ordering key;
different tuple bytes sharing a digest remain different groups.

Allocation uses exact integer deficits, weights3/1/1 over denominator5. Process mixed-label
groups first, then pure benign, then pure malicious. Sort each stratum by
SHA256(`1729:` + tuple digest hex), then tuple digest, then tuple bytes, bytewise ascending.
For each intact group choose the partition maximizing the sum, over labels present in that
group, of `weight[p]*total_class_rows - 5*already_assigned_class_rows[p]`. Break ties in
TRAIN/VALIDATION/TEST order. Mixed groups retain both counts and block adoption; computing
their diagnostic membership neither resolves conflicts nor removes observations.
Without mixed groups this reproduces the prior pure-class absolute-deficit proposal.

Invalid category means empty, outer whitespace or case-insensitive nan/null/none token.
Any other source string is structurally valid. Valid-but-unseen relative to TRAIN is a
separate diagnostic and blocks the frozen `handle_unknown=error` preprocessing. Do not
expand vocabulary from VALIDATION/TEST, force category representatives into TRAIN,
reinterpret unseen values as invalid, or change features/seed/labels based on diagnostics.
The prior smoke's forced category coverage was a diagnostic fixture; it is not reused here.

Membership is source-list order then numeric 1-based source row order, exact compact UTF8
JSON arrays `[relative_path,index,pkSeqID_string,attack_string,equivalence_digest_hex]`,
one LF per row. Store external diagnostic membership files and SHA256s, no X training
matrices or official package. Replay allocation independently from fixed exact groups.
Support minima remain rows100/50/50 and groups20/10/10 per class. Failures are blockers;
do not reroll. All policy/implementation changes are committed before the real full scan.

Smoke terminology clarification, to be confirmed against the same selected source rows:
10,328 observations minus6,164 excess =4,164 unique X groups. Of those,1,365 are repeated
groups and2,799 singletons; rows involved in repeats =6,164+1,365=7,529. The earlier term
"duplicate groups" means repeated groups, not all groups or duplicated observations.
Historical smoke JSON/handoff are retained; full verification provides a separate addendum.

This is an independent A2 binary benign/malicious experiment proposal, **not ADOPTED**.
Machine-readable authority for this proposal:
[candidate contract](../../artifacts/contracts/bot_iot_secondary_ml_candidate_v1.json).
Existing G2A contracts, G3A primary split and closed primary package remain unchanged.

## Sources, semantics and predictors

Only the four canonical All-features 5% shards are eligible. Do not mix 10-best files or
adopt their supplied train/test membership. The lineage audit finds numeric differences
between representations even when IDs match. No feature-matrix merge with N-BaIoT.

Ordered pre-encoding X (13 fields):

`pkts, bytes, dur, spkts, dpkts, sbytes, dbytes, rate, srate, drate, flgs, proto, state`.

The first ten describe transaction counts/duration/rates; the last three are text categories
encoded without treating their numerical aliases as ordered quantities. Retaining both
total and directional statistics is a simple initial choice; no score-based feature selection.

| Group | Decision and reason |
| --- | --- |
| attack/category/subcategory | Target metadata only; exact attack `0 -> benign`, `1 -> malicious`. |
| pkSeqID | Identifier/lineage only; audit establishes uniqueness and strong label-range alignment. |
| stime/ltime/seq | Exclude time/order shortcuts; preserve in context metadata. |
| IPs and ports | Exclude entity/context predictors in this initial candidate; preserve context and lossless port parsing. |
| flgs_number/proto_number/state_number | Exclude aliases of selected text fields. |
| mean/stddev/sum/min/max | Exclude pending aggregation-boundary evidence; workbook calls these duration statistics of aggregated records. |
| Tn* | Exclude supplied cross-record bytes/packet totals per IP, protocol or destination port. |
| AR_P_* | Exclude supplied rates grouped by protocol and IP/port. |
| N_IN_Conn_* | Exclude inbound connection counts per IP. |
| Pkts_P_State_* | Exclude packet counts grouped by state, protocol and IP. |

Semantics were read from local `Total Feature Description.xlsx` (path/hash in candidate).
It does not establish the aggregate window, causal availability or whether groups cross
an evaluation boundary. Exclusion is conservative; it is not a finding that every supplied
aggregate leaks. Transaction fields also describe completed transactions; no early-detection
or point-in-time streaming claim follows.

## Assembly and preprocessing

Reuse `bot_iot.py` to enforce the 46-column source schema and canonical source paths.
`bot_iot_secondary.py` assembles X separately from y, identifiers, target metadata and context.
Numeric columns are finite, nonnegative float64; packet/byte counts must be integral and
within exact float64 integer range. Zero duration/rates remain legitimate zeros: do not
recompute rates by division or invent missing values. Invalid/missing selected values
fail closed with no imputation, clipping or silent row removal.

Categories retain exact case and internal spaces; empty/outer-whitespace/null tokens fail.
Ports use the canonical decimal/hex parser. `-1` remains unresolved with `value=None`,
distinct from port zero; ports do not enter X.

Fit StandardScaler and OneHotEncoder once on TRAIN. VALIDATION/TEST transform only.
Persist learned vocabulary, actual encoded order, scaler and hashes. Unknown categories
fail closed rather than collapsing different values into all-zero vectors. If official
held-out categories are unseen, record a blocker and review the protocol; do not silently
change encoding or search seeds. No PCA, SMOTE, default balancing or local model fitting.

## Split comparison using existing audits, not model scores

Existing audits cover 3,668,522 rows: benign 477; malicious 3,668,045 (about 7,690:1).
The following are **historical audit observations**, not newly materialised memberships:

| Candidate | Support/evidence | Assessment |
| --- | --- | --- |
| B2 random stratified, seed1729, subcategory, 80/20 | benign 382/95; malicious 2,934,435/733,610; test saddr overlap 100% | Supports within-corpus comparison, but ordinary row splitting can separate new effective duplicates. |
| B3 temporal, audited stime threshold | TRAIN benign477; TEST benign0, malicious733,719 | Cannot estimate benign recall/FPR or a supported binary macro-F1; do not fix by relabelling or resampling TEST. |
| B4 saddr grouped | benign370/107; malicious2,773,737/895,308; TEST24.41% | Useful unseen-source sensitivity experiment, but needs an inner split, equivalence unions and enough distinct benign groups. |
| B4 saddr+daddr grouped | benign421/56; TEST23.06%; no test data-exfiltration subtype | Benign estimate fragile (~1.79 percentage points per error); not selected as default. |
| B1 supplied 10-best | benign370/107; different representation; temporal interleaving | Reference only; not adopted group split. |

Propose a new **binary-stratified effective-equivalence-group 60/20/20 split**, seed1729.
This is not `primary_split_v1` and does not inherit B2 membership. Exact algorithm,
canonical group serialization and tie rules are in the candidate JSON. Keep equivalent X
rows together; confirm tuple equality within hash groups. Conflicting binary labels are
a review blocker, not a reason to choose one label or move rows across groups.

Without grouping, nominal benign support is approximately 286/95/96; these are estimates,
not observed official counts. Require at least 100/50/50 rows and 20/10/10 distinct groups
per class for TRAIN/VALIDATION/TEST. These proposed minima prevent undefined estimates;
they do not guarantee precise benign performance. At support95 one error changes recall
by ~1.05 percentage points. Report binomial intervals and group-aware uncertainty.

The bounded smoke already finds 1,365 duplicate groups (6,164 excess rows) in this new
feature space. Historical zero duplicates in all-fields-minus-ID/seq does not transfer to
13 predictors. **Full candidate-specific equivalence/group-support scanning is still
required before adoption and official membership.** This targeted new question justifies
a later scan; it is not a rerun of all G1/G2 audits.

Preserve all evaluation rows and natural row weights/prevalence. Report row-weighted
metrics plus group-weighted sensitivity to repeated observations. Keep TEST sealed for
model selection; choose hyperparameters/thresholds only using TRAIN/VALIDATION. Report
confusion counts, both class supports/recalls, malicious precision, FPR and macro-F1;
accuracy is supplementary. Fix threshold0.5 for initial classifiers unless a reviewed
validation-only threshold procedure is adopted. Use a most-frequent Dummy comparator.
No classifier family is adopted by this preparation checkpoint.

## Identity, resources and scope

Materialise actual sorted memberships and hash exact serialized rows per partition as
specified in JSON; include source row ID, target and candidate equivalence key. Bind results
to package/contract/split/membership/preprocessor/code identities. Never label a sampled
TRAIN with the full TRAIN hash. Use a new secondary package namespace and checksum manifest.

If full TRAIN is too large, propose a separate deterministic malicious TRAIN group-sampling
policy with actual counts and fingerprints **before** official fitting. Do not change
VALIDATION/TEST prevalence. This checkpoint neither downsamples nor builds an official package.

Conclusions apply to the audited 5% capture with shared environments/campaigns potentially
remaining across partitions. They do not establish future-time, unseen-device/network,
full Bot-IoT, N-BaIoT transfer or deployment performance. Entity-grouped sensitivity can
be reviewed separately. All classifier/clustering fitting, including smoke, runs on Kaggle.
