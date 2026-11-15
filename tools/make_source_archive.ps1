# Writes dist\STRPluginMessagingAPI_<version>_source.zip: the tracked files at HEAD (git archive) plus the pinned source of every
# git submodule (recursively) Entry names use forward slashes under STRPluginMessagingAPI_<version>_source/.
# Never overwrites an earlier archive (a _yyyyMMdd-HHmmss suffix is added).
#   -Version              default: the version in CMakeLists.txt (CI passes the tag's version, e.g. 0.2.2-test1)
#   -OverlayWorkingTree   also copy tracked files modified in the working tree over the HEAD copy (CI uses this
#                         because the release workflow stamps the version into files without committing)
param(
    [string]$Version = "",
    [switch]$OverlayWorkingTree
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dist = Join-Path $root "dist"
if (-not $Version) {
    $cmake = [System.IO.File]::ReadAllText((Join-Path $root "CMakeLists.txt"))
    $m = [regex]::Match($cmake, '(?s)project\(\s*STRPluginMessagingAPI\s+VERSION ([0-9]+\.[0-9]+\.[0-9]+)')
    if (-not $m.Success) { throw "Could not read the version from CMakeLists.txt" }
    $Version = $m.Groups[1].Value
}

# Never replace an earlier build: if the target already exists, add a _yyyyMMdd-HHmmss suffix before the extension.
function Get-UniquePath([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $Path }
    $dir  = Split-Path -Parent $Path
    $base = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    $ext  = [System.IO.Path]::GetExtension($Path)
    return (Join-Path $dir ("{0}_{1}{2}" -f $base, (Get-Date -Format "yyyyMMdd-HHmmss"), $ext))
}

function Invoke-Git {
    $out = & git @args
    if ($LASTEXITCODE -ne 0) { throw ("git {0} failed" -f ($args -join ' ')) }
    return $out
}

$top = "STRPluginMessagingAPI_${Version}_source"
$stage = Join-Path ([System.IO.Path]::GetTempPath()) ("STRPluginMessagingAPI_src_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $stage | Out-Null
try {
    $content = Join-Path $stage "content"
    New-Item -ItemType Directory -Path $content | Out-Null
    Push-Location $root
    try {
        # 1. The repository itself, tracked files at HEAD.
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $tmpZip = Join-Path $stage "root.zip"
        Invoke-Git archive --format=zip -o $tmpZip HEAD | Out-Null
        [System.IO.Compression.ZipFile]::ExtractToDirectory($tmpZip, $content)
        Remove-Item -LiteralPath $tmpZip

        # 2. Every submodule (nested ones too) at the commit this repo pins.
        $lines = @(Invoke-Git submodule status --recursive)
        foreach ($line in $lines) {
            if (-not $line.Trim()) { continue }
            if ($line[0] -eq '-') { throw "Submodule not checked out: $line. Run: git submodule update --init --recursive" }
            if ($line -notmatch '^[ +U]?([0-9a-f]{40}) (\S+)') { throw "Cannot parse submodule line: $line" }
            $sha = $Matches[1]; $path = $Matches[2]
            $subZip = Join-Path $stage "sub.zip"
            Invoke-Git -C $path archive --format=zip -o $subZip $sha | Out-Null
            $dest = Join-Path $content $path
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            [System.IO.Compression.ZipFile]::ExtractToDirectory($subZip, $dest)
            Remove-Item -LiteralPath $subZip
            Write-Host ("Submodule {0} at {1}" -f $path, $sha.Substring(0, 12))
        }

        # 3. CI: the working tree carries the stamped version; HEAD does not.
        if ($OverlayWorkingTree) {
            foreach ($rel in @(Invoke-Git diff --name-only HEAD)) {
                if (-not $rel) { continue }
                $src = Join-Path $root $rel
                if (Test-Path -LiteralPath $src -PathType Leaf) {
                    Copy-Item -LiteralPath $src -Destination (Join-Path $content $rel) -Force
                    Write-Host "Overlaid working-tree change: $rel"
                }
            }
        }
    } finally {
        Pop-Location
    }

    # 4. The credits and the source pointer must be tracked.
    foreach ($required in @("CREDITS.md", "package/Docs/SOURCE.txt")) {
        if (-not (Test-Path -LiteralPath (Join-Path $content $required))) { throw "$required is not tracked in this repository." }
    }

    New-Item -ItemType Directory -Path $dist -Force | Out-Null
    $zip = Get-UniquePath (Join-Path $dist ("STRPluginMessagingAPI_{0}_source.zip" -f $Version))

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::Open($zip, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        $prefix = (Resolve-Path -LiteralPath $content).Path.TrimEnd('\') + '\'
        foreach ($file in Get-ChildItem -LiteralPath $content -Recurse -File -Force) {
            $name  = $top + "/" + $file.FullName.Substring($prefix.Length).Replace('\', '/')
            $entry = $archive.CreateEntry($name, [System.IO.Compression.CompressionLevel]::Optimal)
            $in    = [System.IO.File]::OpenRead($file.FullName)
            $out   = $entry.Open()
            try { $in.CopyTo($out) } finally { $out.Dispose(); $in.Dispose() }
        }
    } finally {
        $archive.Dispose()
    }
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host ""
Write-Host "Source archive written to: $zip"
