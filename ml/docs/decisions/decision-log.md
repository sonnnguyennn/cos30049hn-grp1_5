# Decision log

> Internal engineering record. “Pending” entries are explicitly not decisions.

## Established project direction

| Item | Status | Basis |
|---|---|---|
| Topic: Network Traffic Classification for Anomaly Detection | Locked | Project direction |
| Core input: structured network-traffic features | Locked | Project scope |
| Web layer: React.js frontend and FastAPI backend | Locked | Assignment 3 direction |
| Edge evaluation platform: Raspberry Pi 4 | Locked | Project direction |
| Edge work must not block the required core pipeline | Locked | Delivery constraint |
| Raw PCAP processing and live capture are outside core scope | Locked | Scope boundary |
| Investigate supervised classification and unsupervised clustering | Locked | Evaluation direction |
| Primary dataset: N-BaIoT | Accepted | ADR-001; A0-A7 evidence chain |
| Secondary dataset: Bot-IoT | Accepted | ADR-001; bounded future ML experiment required |
| Core supervised target: benign vs malicious | Locked | ADR-001 project-specific role decision |
| Direct N-BaIoT/Bot-IoT feature-matrix merge | Excluded from core pipeline | ADR-001; no verified common input space |
| Canonical N-BaIoT candidate schema: ordered 115 source fields | Specified | G2A feature contract v1.0.0 |
| Canonical Bot-IoT secondary source: four All-features 5% shards | Specified | G2A secondary source contract v1.0.0 |
| Deterministic canonical parsing: strict streaming, exact lexical group ID before numeric parse | Implemented locally | G2B preprocessing contract |
| Learned transforms: fit on training partition only after G3 | Boundary specified; no fitted implementation | G2B preprocessing contract |
| Stable source observation identity: logical source ID + 1-based data-row index | Locked | G2C reproducibility validation |
| Primary canonical traversal: ascending logical ID, then physical row order | Locked | G2C traversal manifest |
| G2 canonical data layer closure | Complete | Full 7,062,606-row dry run and independent G2C verification |
| G3A split rule | Adopted | `primary_split_v1`; all predeclared gates and independent full-corpus verification passed |

## Pending decisions

| Item | Required evidence / trigger |
|---|---|
| Supplementary use of family/fine/category labels | G2/G3 experiment design |
| Exact feature schema | Dataset compatibility and leakage analysis |
| Final classifier | Protocol-led reproducible evaluation |
| Exact edge deployment format | Final pipeline and Pi compatibility evidence |
