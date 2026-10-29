# Shared inference contract

> Internal template; fields marked TBD are not decisions.

The same versioned preprocessing and prediction behavior should be reused by offline evaluation, CLI inference, FastAPI, and Raspberry Pi execution.

## Contract fields

| Field | Value |
|---|---|
| Contract version | TBD |
| Input schema and order | TBD after dataset audit |
| Data types and allowed ranges | TBD |
| Missing/invalid value policy | TBD |
| Preprocessor identifier and SHA-256 | TBD |
| Model identifier and SHA-256 | TBD |
| Output labels and semantics | TBD |
| Error schema | TBD |
| Compatibility policy | TBD |

Future releases should include valid, boundary, and invalid inference test vectors so every runtime can be checked against identical expected behavior.
