# 4.4 handoff check, run 06 - PASS

Environment: Conda env `duy-iotguard-check-06` created from the bundle's environment.yml.

| Step | Status | Detail |
|---|---|---|
| operating system | INFO | Microsoft Windows 11 Pro 10.0.22631 (build 22631, 64-bit) |
| PowerShell | INFO | 5.1.22621.6133 |
| ZIP SHA-256 | PASS | 6ff11f67d25c75822b51936cfa22a7746b6a28ed7f2cc4de7b39cfee89ed6d77 |
| extract to new folder + manifest.json SHA-256 | PASS | 9fac1acde3f696bb765937c997977b3d7b1e1c2fa6cd60626e910037ea1fe132 |
| conda executable | INFO | D:\miniconda3\Scripts\conda.exe |
| conda available | PASS | conda 26.9.4 |
| conda env create -n duy-iotguard-check-06 -f environment.yml | PASS | exit code 0 |
| predict_primary.py --verify | PASS | status PASS |
| predict_primary.py --input example_input.json | PASS | exit code 0 |
| outputs match example_expected.json (labels benign, malicious, benign; 3rd = known FN) | PASS | 15 checks |

## Commands

    [conda_version] (cwd C:\Users\SV STORE\iotguard_4_4_check\handoff_06) conda.exe --version
    [conda_env_list_before] (cwd C:\Users\SV STORE\iotguard_4_4_check\handoff_06) conda.exe env list
    [conda_env_create] (cwd C:\Users\SV STORE\iotguard_4_4_check\handoff_06) conda.exe env create -n duy-iotguard-check-06 -f environment.yml
    [conda_list] (cwd C:\Users\SV STORE\iotguard_4_4_check\handoff_06) conda.exe list -n duy-iotguard-check-06 --export
    [pip_freeze] (cwd C:\Users\SV STORE\iotguard_4_4_check\handoff_06) conda.exe run -n duy-iotguard-check-06 python -m pip freeze
    [python_version] (cwd C:\Users\SV STORE\iotguard_4_4_check\handoff_06) conda.exe run -n duy-iotguard-check-06 python --version
    [verify] (cwd C:\Users\SV STORE\iotguard_4_4_check\handoff_06) conda.exe run --no-capture-output -n duy-iotguard-check-06 python -I predict_primary.py --bundle . --expected-manifest 9fac1acde3f696bb765937c997977b3d7b1e1c2fa6cd60626e910037ea1fe132 --verify --output ../evidence_06/duy_verification_06.json
    [predict] (cwd C:\Users\SV STORE\iotguard_4_4_check\handoff_06) conda.exe run --no-capture-output -n duy-iotguard-check-06 python -I predict_primary.py --bundle . --expected-manifest 9fac1acde3f696bb765937c997977b3d7b1e1c2fa6cd60626e910037ea1fe132 --input example_input.json --output ../evidence_06/duy_predictions_06.json
    [compare] (cwd C:\Users\SV STORE\iotguard_4_4_check\handoff_06) conda.exe run --no-capture-output -n duy-iotguard-check-06 python -I ../t44_compare_outputs_06.py --bundle . --verification ../evidence_06/duy_verification_06.json --predictions ../evidence_06/duy_predictions_06.json --output ../evidence_06/comparison_06.json
