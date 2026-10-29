# Secondary Bot-IoT data contract v1

> G2A specification only. No secondary experiment, split, transform, or model is selected.

## Canonical source representation

The canonical secondary representation is the audited four-shard All-features 5% source with one ordered 46-column schema:

- `Dataset/5%/All features/UNSW_2018_IoT_Botnet_Full5pc_1.csv`
- `Dataset/5%/All features/UNSW_2018_IoT_Botnet_Full5pc_2.csv`
- `Dataset/5%/All features/UNSW_2018_IoT_Botnet_Full5pc_3.csv`
- `Dataset/5%/All features/UNSW_2018_IoT_Botnet_Full5pc_4.csv`

The 10-best full file is a derived reference representation. Supplied 10-best train/test files are a derived reference split and are not an adopted evaluation split. Representations must not be mixed silently.

## Field boundaries

- `attack`, `category`, and `subcategory`: target metadata; prohibited as ordinary predictors.
- `pkSeqID`: identifier/lineage metadata; prohibited as an ordinary predictor.
- The unnamed 10-best physical index: reference-only identifier metadata.
- `stime`, `ltime`, and `seq`: temporal/order-sensitive; eligibility deferred.
- Addresses and ports: entity/context-sensitive; eligibility deferred.
- Remaining traffic-derived fields: behavioral/statistical candidates, not a selected predictor set.

## Port lexical contract

Raw `sport` and `dport` lexemes are preserved. Decimal strings use base 10; `0x`-prefixed strings use base 16. `-1` remains an unresolved sentinel and is neither an ordinary port nor imputed in G2A.

## Cross-dataset boundary

Direct feature-matrix merging is prohibited in the core pipeline. N-BaIoT and Bot-IoT input spaces are not interchangeable, and direct cross-dataset evaluation remains `NOT_CURRENTLY_DEFENSIBLE`.
