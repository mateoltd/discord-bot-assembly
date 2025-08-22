param(
    [string]$Configuration = "Debug"
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$src = Join-Path $root 'src'
$build = Join-Path $root 'build'

if (!(Test-Path $build)) { New-Item -ItemType Directory -Path $build | Out-Null }

function Find-Tool($name) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Path }

    # Try vswhere (if available) to locate latest VS tools
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
    if (Test-Path $vswhere) {
        $pattern = switch -Regex ($name.ToLower()) {
            'ml64\.exe' { 'VC/Tools/MSVC/**/bin/Hostx64/x64/ml64.exe' ; break }
            'link\.exe' { 'VC/Tools/MSVC/**/bin/Hostx64/x64/link.exe' ; break }
            default { $null }
        }
        if ($pattern) {
            $tool = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find $pattern 2>$null
            if ($tool) { return $tool.Trim() }
        }
    }
    return $null
}

function Find-WinSdkLibPath() {
    # Prefer environment set by VS dev prompt
    if ($env:WindowsSdkDir -and $env:WindowsSDKLibVersion) {
        $p = Join-Path $env:WindowsSdkDir (Join-Path 'Lib' (Join-Path $env:WindowsSDKLibVersion 'um/x64'))
        if (Test-Path $p) { return $p }
    }
    # Probe common install locations
    $kitRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10/Lib'
    if (Test-Path $kitRoot) {
        $ver = Get-ChildItem $kitRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1
        if ($ver) {
            $umx64 = Join-Path $ver.FullName 'um/x64'
            if (Test-Path $umx64) { return $umx64 }
        }
    }
    return $null
}

$ml64 = Find-Tool 'ml64.exe'
$link = Find-Tool 'link.exe'
$winsdkLib = Find-WinSdkLibPath

if (-not $ml64 -or -not $link) {
    Write-Host "[!] Could not find ml64.exe or link.exe in PATH."
    Write-Host "    - Open the 'x64 Native Tools Command Prompt for VS' and run this script"
    Write-Host "    - Or install Visual Studio Build Tools + Windows 10/11 SDK"
    exit 1
}

$exe = Join-Path $build 'bot.exe'

# Assemble all .asm files
Write-Host "[ml64] $ml64"
$asmFiles = Get-ChildItem $src -Filter *.asm | ForEach-Object { $_.FullName }
if ($asmFiles.Count -eq 0) { throw "No .asm files found in $src" }
$objs = @()
foreach ($f in $asmFiles) {
    $name = [System.IO.Path]::GetFileNameWithoutExtension($f)
    $out = Join-Path $build ("{0}.obj" -f $name)
    Write-Host "  assembling $name.asm -> $(Split-Path -Leaf $out)"
    & $ml64 /nologo /c /Zi /Fo $out $f
    if ($LASTEXITCODE -ne 0) { throw "ml64 failed on $f" }
    $objs += $out
}

# Link
Write-Host "[link] $link"
$libArgs = @()
if ($winsdkLib) { $libArgs += "/LIBPATH:$winsdkLib" }
& $link /nologo /DEBUG /SUBSYSTEM:CONSOLE /ENTRY:main $objs kernel32.lib ws2_32.lib /OUT:$exe @libArgs
if ($LASTEXITCODE -ne 0) { throw "link failed" }

Write-Host "Build succeeded: $exe"
