param(
    [string]$Branch = 'HEAD',
    [string]$OutputDirectory = 'reports/gitinspector'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not (Get-Command gitinspector -ErrorAction SilentlyContinue)) {
    throw 'gitinspector is missing. See docs/gitinspector.md for installation.'
}

Push-Location $repoRoot
$previousEncoding = [Console]::OutputEncoding
$previousPythonEncoding = $env:PYTHONIOENCODING
try {
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $env:PYTHONIOENCODING = 'utf-8'
    $revision = & git rev-parse --verify ($Branch + '^{commit}')
    if ($LASTEXITCODE -ne 0) { throw "Unknown branch or revision: $Branch" }
    $safeBranch = $Branch -replace '[^a-zA-Z0-9._-]', '_'
    $destination = Join-Path $OutputDirectory $safeBranch
    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    $repository = if ($Branch -eq 'HEAD') { '.' } else { '.:' + $Branch }
    $common = @('--timeline', '--responsibilities', '--list-file-types', '--localize-output=false')
    $profiles = @{
        source = 'py,js,mjs,ts,tsx,jsx,css,scss,html,sql,sh,ps1'
        all = '**'
    }
    foreach ($profile in @('source', 'all')) {
        foreach ($format in @('html', 'text')) {
            $extension = if ($format -eq 'text') { 'txt' } else { 'html' }
            $output = & gitinspector @common "--file-types=$($profiles[$profile])" "--format=$format" $repository
            if ($LASTEXITCODE -ne 0) { throw "gitinspector failed: $profile / $format" }
            $output | Set-Content -Encoding UTF8 -Path (Join-Path $destination "$profile.$extension")
        }
    }
    @(
        "Generated: $([DateTimeOffset]::Now.ToString('o'))"
        "Branch/revision: $Branch"
        "Commit: $revision"
        "Reachable commits: $(& git rev-list --count $Branch)"
        ''
        'Commit counts by author (all file types, including merge commits):'
        (& git shortlog -sne $Branch)
        ''
        'Reports use only history reachable from the selected revision.'
        'source: selected code extensions; all: every tracked file type.'
        'Gitinspector counts commits matching the selected file types.'
        'Line counts and commit counts do not measure contribution quality.'
    ) | Set-Content -Encoding UTF8 -Path (Join-Path $destination 'scope.txt')
    Write-Host "Reports written to $([IO.Path]::GetFullPath($destination))"
}
finally {
    [Console]::OutputEncoding = $previousEncoding
    $env:PYTHONIOENCODING = $previousPythonEncoding
    Pop-Location
}
