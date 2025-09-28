$HELPERS_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path

function profile_add_helpers { 
    $sourceLine = '. ' + "$HELPERS_DIR/init.ps1"
    if (-not (Test-Path $profile)) {
        $folder = [System.IO.Path]::GetDirectoryName($profile)
        New-Item -Path $folder -ItemType Directory | Out-Null
        New-Item $profile -type file | Out-Null
    } elseif (-not (Select-String -Path $profile -SimpleMatch $sourceLine -Quiet)) {
        Add-Content $profile $sourceLine
    }
    log_msg "init.ps1 added to $profile"
}

# -- load os/<name>.ps1 files -- 

. "$HELPERS_DIR/os/any.ps1"
. "$HELPERS_DIR/os/win.ps1"

# -- load <program>.ps1 files --

$helpersDir = "$PSScriptRoot/programs"

Get-ChildItem -Path "$helpersDir\*.ps1" | ForEach-Object {
    $program = $_.BaseName
    if (Get-Command $program -ErrorAction SilentlyContinue) {
        . $_.FullName
    }
}
