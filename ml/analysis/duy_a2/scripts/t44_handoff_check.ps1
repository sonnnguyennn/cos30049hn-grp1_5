<#
.SYNOPSIS
  CODE 4.4.1-4.4.3 - clean-environment check of the IoTGuard primary XGBoost handoff (Duy).

.DESCRIPTION
  Follows the handoff README with a NEW Conda environment and records evidence:
    1. SHA-256 of the handoff ZIP must equal the published value.
    2. Extracts it into a NEW folder (never re-uses an earlier extraction).
    3. conda env create -n duy-iotguard-check-<RunId> -f environment.yml
    4. predict_primary.py --verify   ->  evidence_<RunId>\duy_verification_<RunId>.json
    5. predict_primary.py --input example_input.json -> evidence_<RunId>\duy_predictions_<RunId>.json
    6. t44_compare_outputs.py inside the same env  -> comparison_<RunId>.json
  Writes transcript, per-command stdout/stderr, conda list, OS info and checklist_<RunId>.md/.json.
  Never edits the bundle, manifest, model or example files. If a step fails, keep the evidence
  folder, fix the cause and rerun with a new -RunId (02, 03, ...).

.EXAMPLE
  # From the "Anaconda PowerShell Prompt" (or any PowerShell where `conda` works):
  powershell -ExecutionPolicy Bypass -File .\t44_handoff_check.ps1 `
      -HandoffZip "$HOME\Downloads\IoTGuard_Primary_XGBoost_Handoff.zip" -RunId 01
#>
param(
    [Parameter(Mandatory = $true)][string]$HandoffZip,
    [string]$WorkRoot = (Join-Path $HOME "iotguard_4_4_check"),
    [string]$RunId = "01"
)

$ErrorActionPreference = "Stop"   # native stdout/stderr are redirected and exit codes checked separately
$ExpectedZip = "6ff11f67d25c75822b51936cfa22a7746b6a28ed7f2cc4de7b39cfee89ed6d77"
$ExpectedManifest = "9fac1acde3f696bb765937c997977b3d7b1e1c2fa6cd60626e910037ea1fe132"
$EnvName = "duy-iotguard-check-$RunId"
$Bundle = Join-Path $WorkRoot "handoff_$RunId"
$Evidence = Join-Path $WorkRoot "evidence_$RunId"
$EvidenceRel = "../evidence_$RunId"          # relative paths avoid spaces in "C:\Users\SV STORE\..."; "/" works on Windows too
$Steps = New-Object System.Collections.ArrayList
$Commands = New-Object System.Collections.ArrayList

function Add-Step([string]$Name, [string]$Status, [string]$Detail) {
    [void]$Steps.Add([ordered]@{ step = $Name; status = $Status; detail = $Detail })
    Write-Host ("[{0}] {1} - {2}" -f $Status, $Name, $Detail)
}

function Invoke-Logged([string]$Exe, [string[]]$ArgList, [string]$WorkDir, [string]$LogName) {
    $out = Join-Path $Evidence "$LogName.stdout.txt"
    $err = Join-Path $Evidence "$LogName.stderr.txt"
    [void]$Commands.Add(("[{0}] (cwd {1}) {2} {3}" -f $LogName, $WorkDir, (Split-Path $Exe -Leaf), ($ArgList -join " ")))
    $p = Start-Process -FilePath $Exe -ArgumentList $ArgList -WorkingDirectory $WorkDir `
        -RedirectStandardOutput $out -RedirectStandardError $err -NoNewWindow -PassThru
    $null = $p.Handle          # keeps ExitCode available on Windows PowerShell 5.1
    $p.WaitForExit()
    Get-Content $out | ForEach-Object { Write-Host "  $_" }
    Get-Content $err | ForEach-Object { Write-Host "  $_" }
    return $p.ExitCode
}

function Write-Checklist([string]$Overall) {
    $summary = [ordered]@{
        run_id = $RunId; overall = $Overall; created = (Get-Date).ToString("o")
        handoff_zip = (Split-Path $HandoffZip -Leaf); conda_env = $EnvName
        steps = $Steps; commands = $Commands
    }
    $summary | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 (Join-Path $Evidence "checklist_$RunId.json")
    $md = @("# 4.4 handoff check, run $RunId - $Overall", "",
            "Environment: Conda env ``$EnvName`` created from the bundle's environment.yml.", "",
            "| Step | Status | Detail |", "|---|---|---|")
    foreach ($s in $Steps) { $md += ("| {0} | {1} | {2} |" -f $s.step, $s.status, ($s.detail -replace "\|", "/")) }
    $md += @("", "## Commands", "")
    foreach ($c in $Commands) { $md += ("    " + $c) }
    $md | Set-Content -Encoding UTF8 (Join-Path $Evidence "checklist_$RunId.md")
}

if (Test-Path $Bundle) { throw "$Bundle already exists. Use a new -RunId (e.g. 02)." }
if (Test-Path $Evidence) { throw "$Evidence already exists. Use a new -RunId (e.g. 02)." }
New-Item -ItemType Directory -Force -Path $Evidence | Out-Null
Start-Transcript -Path (Join-Path $Evidence "transcript_$RunId.txt") | Out-Null
$overall = "FAIL"
try {
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $osText = "{0} {1} (build {2}, {3})" -f $os.Caption, $os.Version, $os.BuildNumber, $os.OSArchitecture
    } catch {
        $osText = [System.Environment]::OSVersion.VersionString
    }
    $osText | Set-Content -Encoding UTF8 (Join-Path $Evidence "os_$RunId.txt")
    Add-Step "operating system" "INFO" $osText
    Add-Step "PowerShell" "INFO" $PSVersionTable.PSVersion.ToString()

    # 1. ZIP checksum
    if (-not (Test-Path -LiteralPath $HandoffZip)) { Add-Step "handoff ZIP found" "FAIL" $HandoffZip; throw "ZIP not found" }
    $zipHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $HandoffZip).Hash.ToLower()
    if ($zipHash -ne $ExpectedZip) { Add-Step "ZIP SHA-256" "FAIL" $zipHash; throw "ZIP checksum mismatch" }
    Add-Step "ZIP SHA-256" "PASS" $zipHash

    # 2. fresh extraction + manifest identity
    Expand-Archive -LiteralPath $HandoffZip -DestinationPath $Bundle
    foreach ($f in @("README.md", "environment.yml", "predict_primary.py", "manifest.json", "example_input.json", "example_expected.json")) {
        if (-not (Test-Path (Join-Path $Bundle $f))) { Add-Step "bundle file $f" "FAIL" "missing after extraction"; throw "bundle incomplete" }
    }
    $manifestHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $Bundle "manifest.json")).Hash.ToLower()
    if ($manifestHash -ne $ExpectedManifest) { Add-Step "manifest.json SHA-256" "FAIL" $manifestHash; throw "manifest mismatch" }
    Add-Step "extract to new folder + manifest.json SHA-256" "PASS" $manifestHash
    Copy-Item (Join-Path $PSScriptRoot "t44_compare_outputs.py") (Join-Path $WorkRoot "t44_compare_outputs_$RunId.py")

    # 3. conda + NEW environment
    $condaExe = $env:CONDA_EXE
    if (-not $condaExe) { $cmd = Get-Command conda.exe -ErrorAction SilentlyContinue; if ($cmd) { $condaExe = $cmd.Source } }
    if (-not $condaExe -or -not (Test-Path $condaExe)) {
        Add-Step "conda available" "FAIL" "conda.exe not found; open the 'Anaconda PowerShell Prompt' and rerun"
        throw "conda not found"
    }
    $code = Invoke-Logged $condaExe @("--version") $Bundle "conda_version"
    if ($code -ne 0) { throw "conda --version failed with exit code $code" }
    Add-Step "conda available" "PASS" ((Get-Content (Join-Path $Evidence "conda_version.stdout.txt")) -join " ")
    $code = Invoke-Logged $condaExe @("env", "list") $Bundle "conda_env_list_before"
    if ($code -ne 0) { throw "conda env list failed with exit code $code" }
    $existing = Get-Content (Join-Path $Evidence "conda_env_list_before.stdout.txt") | Where-Object { $_ -match ("^\s*" + [regex]::Escape($EnvName) + "\s") }
    if ($existing) { Add-Step "environment name is new" "FAIL" "$EnvName already exists"; throw "env exists" }
    $code = Invoke-Logged $condaExe @("env", "create", "-n", $EnvName, "-f", "environment.yml") $Bundle "conda_env_create"
    if ($code -ne 0) { Add-Step "conda env create" "FAIL" "exit code $code (see conda_env_create.*.txt)"; throw "env create failed" }
    Add-Step "conda env create -n $EnvName -f environment.yml" "PASS" "exit code 0"
    $code = Invoke-Logged $condaExe @("list", "-n", $EnvName, "--export") $Bundle "conda_list"
    if ($code -ne 0) { throw "conda list --export failed with exit code $code" }
    $code = Invoke-Logged $condaExe @("run", "-n", $EnvName, "python", "-m", "pip", "freeze") $Bundle "pip_freeze"
    if ($code -ne 0) { throw "pip freeze failed with exit code $code" }
    $code = Invoke-Logged $condaExe @("run", "-n", $EnvName, "python", "--version") $Bundle "python_version"
    if ($code -ne 0) { throw "python --version failed with exit code $code" }

    # 4-5. the two README commands, run inside the new env
    $verifyOut = "$EvidenceRel/duy_verification_$RunId.json"
    $predOut = "$EvidenceRel/duy_predictions_$RunId.json"
    $code = Invoke-Logged $condaExe @("run", "--no-capture-output", "-n", $EnvName, "python", "-I", "predict_primary.py",
        "--bundle", ".", "--expected-manifest", $ExpectedManifest, "--verify", "--output", $verifyOut) $Bundle "verify"
    if ($code -ne 0) { Add-Step "predict_primary.py --verify" "FAIL" "exit code $code (see verify.*.txt)"; throw "verify failed" }
    $verification = Get-Content -Raw (Join-Path $Evidence "duy_verification_$RunId.json") | ConvertFrom-Json
    Add-Step "predict_primary.py --verify" ($(if ($verification.status -eq "PASS") { "PASS" } else { "FAIL" })) ("status " + $verification.status)
    $code = Invoke-Logged $condaExe @("run", "--no-capture-output", "-n", $EnvName, "python", "-I", "predict_primary.py",
        "--bundle", ".", "--expected-manifest", $ExpectedManifest, "--input", "example_input.json", "--output", $predOut) $Bundle "predict"
    if ($code -ne 0) { Add-Step "predict_primary.py --input example_input.json" "FAIL" "exit code $code"; throw "prediction failed" }
    Add-Step "predict_primary.py --input example_input.json" "PASS" "exit code 0"

    # 6. compare with example_expected.json (inside the same env; also records real versions)
    $code = Invoke-Logged $condaExe @("run", "--no-capture-output", "-n", $EnvName, "python", "-I", "../t44_compare_outputs_$RunId.py",
        "--bundle", ".", "--verification", $verifyOut, "--predictions", $predOut,
        "--output", "$EvidenceRel/comparison_$RunId.json") $Bundle "compare"
    if ($code -ne 0) { Add-Step "outputs match example_expected.json" "FAIL" "see compare.stdout.txt"; throw "comparison failed" }
    Add-Step "outputs match example_expected.json (labels benign, malicious, benign; 3rd = known FN)" "PASS" "15 checks"
    $overall = "PASS"
}
catch {
    Add-Step "stopped" "FAIL" $_.Exception.Message
}
finally {
    Write-Checklist $overall
    Stop-Transcript | Out-Null
    Write-Host ""
    Write-Host "OVERALL: $overall   evidence folder: $Evidence"
    if ($overall -ne "PASS") { Write-Host "Keep this folder, send it to Minh Son, and rerun with -RunId 02 after the fix." }
}
if ($overall -ne "PASS") { exit 1 }
