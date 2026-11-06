# 4.4 handoff check, run 05 - FAIL

Environment: Conda env `duy-iotguard-check-05` created from the bundle's environment.yml.

| Step | Status | Detail |
|---|---|---|
| operating system | INFO | Microsoft Windows 11 Pro 10.0.22631 (build 22631, 64-bit) |
| PowerShell | INFO | 5.1.22621.6133 |
| ZIP SHA-256 | PASS | 6ff11f67d25c75822b51936cfa22a7746b6a28ed7f2cc4de7b39cfee89ed6d77 |
| extract to new folder + manifest.json SHA-256 | PASS | 9fac1acde3f696bb765937c997977b3d7b1e1c2fa6cd60626e910037ea1fe132 |
| conda executable | INFO | D:\miniconda3\Scripts\conda.exe |
| conda available | PASS | conda 26.9.4 |
| conda env create | FAIL | exit code 1 (see conda_env_create.*.txt) |
| stopped | FAIL | env create failed |

## Commands

    [conda_version] (cwd C:\Users\SV STORE\iotguard_4_4_check\handoff_05) conda.exe --version
    [conda_env_list_before] (cwd C:\Users\SV STORE\iotguard_4_4_check\handoff_05) conda.exe env list
    [conda_env_create] (cwd C:\Users\SV STORE\iotguard_4_4_check\handoff_05) conda.exe env create -n duy-iotguard-check-05 -f environment.yml
