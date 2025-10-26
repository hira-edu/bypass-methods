# Publishes the SecurityHooked artifact (formerly STF) within this repository
# and optionally uploads it to a GitHub release via the GitHub CLI.
param(
    [string]$Version = "3.1.0",
    [string]$SourceUrl,
    [string]$ArtifactName = "securityhooked.exe",
    [string]$ReleaseTag,
    [string]$Repo,
    [switch]$Upload
)

$ErrorActionPreference = "Stop"

if (-not $SourceUrl) {
    $SourceUrl = "https://github.com/hira-edu/security-testing-framework/releases/download/v$Version/SecurityTestingFramework.exe"
}

if (-not $ReleaseTag) {
    $ReleaseTag = "securityhooked-v$Version"
}

$repoRoot = Resolve-Path "$PSScriptRoot/../.."
$outputDir = Join-Path $repoRoot "artifacts/securityhooked/$Version"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
$artifactPath = Join-Path $outputDir $ArtifactName

Write-Host "Downloading SecurityHooked $Version from $SourceUrl..."
Invoke-WebRequest -Uri $SourceUrl -OutFile $artifactPath
Write-Host "✔ Saved to $artifactPath"

if ($Upload) {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw "GitHub CLI (gh) is not installed or not on PATH."
    }

    if (-not $Repo) {
        $originUrl = git -C $repoRoot remote get-url origin
        if ($originUrl -match "github\.com[:/](.+?)(\.git)?$") {
            $Repo = $Matches[1]
        } else {
            throw "Unable to infer GitHub repository name. Pass -Repo <owner/repo> explicitly."
        }
    }

    Write-Host "Ensuring release $ReleaseTag exists in $Repo..."
    $releaseExists = $true
    try {
        gh release view $ReleaseTag --repo $Repo | Out-Null
    } catch {
        $releaseExists = $false
    }

    if (-not $releaseExists) {
        gh release create $ReleaseTag --repo $Repo --notes "SecurityHooked $Version" | Out-Null
        Write-Host "✔ Created release $ReleaseTag"
    }

    Write-Host "Uploading $artifactPath to release $ReleaseTag in $Repo..."
    gh release upload $ReleaseTag $artifactPath --repo $Repo --clobber | Out-Null
    Write-Host "✔ Uploaded via GitHub CLI."
} else {
    Write-Host "Upload skipped. Use -Upload to push to GitHub releases."
}
