# System context

> Internal engineering documentation.

## Core path

External structured network-traffic datasets feed a future preprocessing and evaluation pipeline. A selected, packaged preprocessing/model pipeline will later support offline evaluation, CLI inference, FastAPI, and a React client.

## Parallel edge path

Candidate or final packaged models may be evaluated on Raspberry Pi 4 for compatibility, latency, throughput, and resource use. The edge track does not block the required offline ML and web integration path.

## Boundaries

- Raw PCAP processing and live packet capture are outside the core scope.
- Raw datasets remain read-only and outside the repository.
- N-BaIoT is primary and Bot-IoT is secondary under ADR-001; the core supervised objective is
  benign versus malicious.
- G2A contract v1 locks the N-BaIoT 115-field candidate schema and the Bot-IoT canonical secondary
  source representation without selecting final predictors.
- G2B supplies deterministic streaming parsers, exact-vector identity, strict label provenance,
  and Bot-IoT field-role/port primitives without fitting or corpus materialization.
- G2C closes the canonical data layer after a deterministic 89-source/7,062,606-row dry
  validation with no retained processed records.
- G3A adopts the independently verified numeric-equivalence-grouped deterministic 70/15/15
  primary split; TEST is sealed and all learned state must fit on TRAIN only.
- Final predictors, fitted preprocessing, model, API payload, and deployment format remain pending
  later G3 evidence. G3B has not started.
