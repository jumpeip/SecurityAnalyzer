<#
.SYNOPSIS
    Build the SecurityAnalyzer Ghidra extension into an installable .zip.

.DESCRIPTION
    Two build paths:

      - Gradle (default). Uses your Gradle install + Ghidra's official
        support/buildExtension.gradle. This is the path NSA tests against.

      - Direct javac (-NoGradle). Skips Gradle entirely and compiles the
        sources against the jars in your Ghidra install. Useful if Gradle
        misbehaves.

    Either path produces  .\dist\ghidra_<ver>_<rel>_<date>_SecurityAnalyzer.zip
    in the standard Ghidra extension layout, ready for File -> Install Extensions.

.PARAMETER GhidraInstallDir
    Path to your Ghidra install. Default: D:\ghidra_12.2_PUBLIC

.PARAMETER GradleHome
    Path to your Gradle install. Default: D:\gradle-9.5.0

.PARAMETER JavaHome
    Path to a JDK 21 install. If not specified the script probes the
    Ghidra install (support/jdk, support/JDK), $env:JAVA_HOME, and
    finally javac on PATH.

.PARAMETER NoGradle
    Skip Gradle entirely and use the direct javac path.

.PARAMETER Clean
    Wipe build/ and dist/ before building.

.EXAMPLE
    PS> .\build-windows.ps1
    PS> .\build-windows.ps1 -Clean
    PS> .\build-windows.ps1 -NoGradle
    PS> .\build-windows.ps1 -GhidraInstallDir "D:\ghidra_12.2_PUBLIC" -GradleHome "D:\gradle-9.5.0"
#>

[CmdletBinding()]
param(
    [string]$GhidraInstallDir = "D:\ghidra_12.2_PUBLIC",
    [string]$GradleHome       = "D:\gradle-9.5.0",
    [string]$JavaHome         = "",
    [switch]$NoGradle,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Step($msg) {
    Write-Host ""
    Write-Host "==> $msg" -ForegroundColor Cyan
}
function Fail($msg) {
    Write-Host "ERROR: $msg" -ForegroundColor Red
    exit 1
}

# --------------------------------------------------------------------
# 1. Verify Ghidra install + read its version metadata
# --------------------------------------------------------------------
Write-Step "Verifying Ghidra install at $GhidraInstallDir"

if (-not (Test-Path $GhidraInstallDir)) {
    Fail "Ghidra install not found: $GhidraInstallDir"
}
$GhidraPropsFile = Join-Path $GhidraInstallDir "Ghidra\application.properties"
if (-not (Test-Path $GhidraPropsFile)) {
    Fail "Doesn't look like a Ghidra install root: $GhidraInstallDir"
}
$ghidraVersion = (Get-Content $GhidraPropsFile | Select-String '^application\.version=' |
    ForEach-Object { ($_ -split '=', 2)[1] }) -join ''
$ghidraRelName = (Get-Content $GhidraPropsFile | Select-String '^application\.release\.name=' |
    ForEach-Object { ($_ -split '=', 2)[1] }) -join ''
if (-not $ghidraVersion) { $ghidraVersion = "UNKNOWN" }
if (-not $ghidraRelName) { $ghidraRelName = "PUBLIC" }
Write-Host "    Ghidra version: $ghidraVersion ($ghidraRelName)"

# --------------------------------------------------------------------
# 2. Locate JDK 21
# --------------------------------------------------------------------
Write-Step "Locating JDK 21"

if (-not $JavaHome) {
    foreach ($cand in @(
        (Join-Path $GhidraInstallDir "support\jdk"),
        (Join-Path $GhidraInstallDir "support\JDK"),
        $env:JAVA_HOME
    )) {
        if ($cand -and (Test-Path (Join-Path $cand "bin\javac.exe"))) {
            $JavaHome = $cand
            break
        }
    }
}
if (-not $JavaHome) {
    $j = Get-Command javac -ErrorAction SilentlyContinue
    if ($j) { $JavaHome = (Split-Path (Split-Path $j.Source)) }
}
if (-not $JavaHome -or -not (Test-Path (Join-Path $JavaHome "bin\javac.exe"))) {
    Fail "Could not find a JDK with javac.exe. Install JDK 21 and pass -JavaHome <path>."
}
$javacExe = Join-Path $JavaHome "bin\javac.exe"
$jarExe   = Join-Path $JavaHome "bin\jar.exe"
$env:JAVA_HOME = $JavaHome
Write-Host "    JAVA_HOME = $JavaHome"
$javacVer = & $javacExe -version 2>&1
Write-Host "    $javacVer"

# --------------------------------------------------------------------
# 3. Verify source layout
# --------------------------------------------------------------------
Write-Step "Verifying source layout"
$srcRoot = Join-Path $ScriptDir "src\main\java"
foreach ($req in @(
    "extension.properties",
    "Module.manifest",
    "build.gradle",
    "src\main\java\securityanalyzer\SecurityAnalyzerPlugin.java",
    "src\main\java\securityanalyzer\ui\SecurityAnalyzerProvider.java"
)) {
    $p = Join-Path $ScriptDir $req
    if (-not (Test-Path $p)) { Fail "Missing required file: $req" }
}

$buildDir = Join-Path $ScriptDir "build"
$distDir  = Join-Path $ScriptDir "dist"
if ($Clean) {
    Write-Step "Cleaning build/ and dist/"
    if (Test-Path $buildDir) { Remove-Item -Recurse -Force $buildDir }
    if (Test-Path $distDir)  { Remove-Item -Recurse -Force $distDir }
}
New-Item -ItemType Directory -Force -Path $distDir | Out-Null

$datestamp = Get-Date -Format "yyyyMMdd"
$zipName   = "ghidra_${ghidraVersion}_${ghidraRelName}_${datestamp}_SecurityAnalyzer.zip"
$zipPath   = Join-Path $distDir $zipName

# ====================================================================
# Path A: Gradle build (preferred)
# ====================================================================
$gradleSucceeded = $false
if (-not $NoGradle) {
    Write-Step "Attempting Gradle build with $GradleHome"
    $gradleBat = Join-Path $GradleHome "bin\gradle.bat"
    if (-not (Test-Path $gradleBat)) {
        Write-Host "    gradle.bat not found at $gradleBat - falling back to javac." -ForegroundColor Yellow
    } else {
        $env:GHIDRA_INSTALL_DIR = $GhidraInstallDir
        Push-Location $ScriptDir
        try {
            & $gradleBat --no-daemon -PGHIDRA_INSTALL_DIR="$GhidraInstallDir" buildExtension
            $gradleExit = $LASTEXITCODE
            if ($gradleExit -ne 0) {
                Write-Host "    Gradle build failed (exit $gradleExit) - falling back to javac." -ForegroundColor Yellow
            } else {
                # Ghidra's buildExtension drops the zip into ./dist/ by default.
                $built = Get-ChildItem -Path $distDir -Filter "*SecurityAnalyzer*.zip" -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending | Select-Object -First 1
                if ($built) {
                    if ($built.FullName -ne $zipPath) {
                        Move-Item -Force $built.FullName $zipPath
                    }
                    $gradleSucceeded = $true
                } else {
                    Write-Host "    Gradle ran but produced no zip in dist/ - falling back to javac." -ForegroundColor Yellow
                }
            }
        } finally {
            Pop-Location
        }
    }
}

# ====================================================================
# Path B: Direct javac fallback
# ====================================================================
if (-not $gradleSucceeded) {
    Write-Step "Building with direct javac"

    $classDir = Join-Path $buildDir "classes"
    if (Test-Path $classDir) { Remove-Item -Recurse -Force $classDir }
    New-Item -ItemType Directory -Force -Path $classDir | Out-Null

    $ghidraRoot = Join-Path $GhidraInstallDir "Ghidra"
    $jars = Get-ChildItem -Path $ghidraRoot -Recurse -Filter *.jar -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch '-src\.jar$' -and $_.Name -notmatch '-javadoc\.jar$' } |
        Select-Object -ExpandProperty FullName
    if ($jars.Count -lt 5) {
        Fail "Found only $($jars.Count) jars under $ghidraRoot - install incomplete."
    }
    Write-Host "    $($jars.Count) jars on classpath"
    $cpString = ($jars -join ';')

    $sources = Get-ChildItem -Path $srcRoot -Recurse -Filter *.java |
        Select-Object -ExpandProperty FullName
    Write-Host "    $($sources.Count) source files"

    $argFile = Join-Path $buildDir "javac.args"
    $lines = @()
    $lines += "-d"
    $lines += "`"$classDir`""
    $lines += "-cp"
    $lines += "`"$cpString`""
    $lines += "-encoding"
    $lines += "UTF-8"
    $lines += "-source"
    $lines += "21"
    $lines += "-target"
    $lines += "21"
    $lines += "-Xlint:none"
    foreach ($s in $sources) { $lines += "`"$s`"" }
    $lines | Set-Content -Path $argFile -Encoding ASCII

    Write-Host "    Compiling..."
    & $javacExe "@$argFile"
    if ($LASTEXITCODE -ne 0) { Fail "javac failed with exit code $LASTEXITCODE" }

    $classCount = (Get-ChildItem -Recurse $classDir -Filter *.class).Count
    Write-Host "    $classCount .class files produced"

    $stageRoot = Join-Path $buildDir "stage\SecurityAnalyzer"
    if (Test-Path $stageRoot) { Remove-Item -Recurse -Force $stageRoot }
    New-Item -ItemType Directory -Force -Path (Join-Path $stageRoot "lib") | Out-Null

    $jarPath = Join-Path $stageRoot "lib\SecurityAnalyzer.jar"
    Push-Location $classDir
    try {
        & $jarExe cf $jarPath .
        if ($LASTEXITCODE -ne 0) { Fail "jar failed with exit code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
    Write-Host "    Wrote $jarPath ($([math]::Round((Get-Item $jarPath).Length / 1KB, 1)) KB)"

    Copy-Item (Join-Path $ScriptDir "extension.properties") $stageRoot -Force
    Copy-Item (Join-Path $ScriptDir "Module.manifest")      $stageRoot -Force
    if (Test-Path (Join-Path $ScriptDir "README.md")) {
        Copy-Item (Join-Path $ScriptDir "README.md") $stageRoot -Force
    }
    foreach ($d in @("ghidra_scripts","data")) {
        $s = Join-Path $ScriptDir $d
        if (Test-Path $s) { Copy-Item $s $stageRoot -Recurse -Force }
    }

    $propPath = Join-Path $stageRoot "extension.properties"
    $propText = Get-Content $propPath -Raw
    $propText = $propText -replace '@extversion@', $ghidraVersion
    Set-Content -Path $propPath -Value $propText -Encoding ASCII
    Write-Host "    Stamped extension.properties with version=$ghidraVersion"

    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        (Split-Path $stageRoot),
        $zipPath,
        [System.IO.Compression.CompressionLevel]::Optimal,
        $false
    )
}

# --------------------------------------------------------------------
# Verify and report
# --------------------------------------------------------------------
if (-not (Test-Path $zipPath)) {
    Fail "Build completed but zip is missing: $zipPath"
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
try {
    $names = $zip.Entries | ForEach-Object { $_.FullName }
} finally {
    $zip.Dispose()
}
foreach ($r in @("SecurityAnalyzer/extension.properties",
                 "SecurityAnalyzer/Module.manifest")) {
    if (-not ($names -contains $r)) { Fail "Built zip is missing required entry: $r" }
}
$hasJar = $names | Where-Object { $_ -like "SecurityAnalyzer/lib/*.jar" }
if (-not $hasJar) { Fail "Built zip contains no jar under SecurityAnalyzer/lib/." }

$zipSizeKB = [math]::Round((Get-Item $zipPath).Length / 1KB, 1)
Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host "    $zipPath ($zipSizeKB KB)"
Write-Host ""
Write-Host "Install:" -ForegroundColor Yellow
Write-Host "  1. Open Ghidra (Project window)."
Write-Host "  2. File -> Install Extensions -> '+' -> select the zip above."
Write-Host "  3. Restart Ghidra."
Write-Host "  4. Open a program in CodeBrowser."
Write-Host "  5. File -> Configure -> Miscellaneous -> tick 'SecurityAnalyzer'."
Write-Host "  6. Find the new menu under Tools -> Security Analyzer."
