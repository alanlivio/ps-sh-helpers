$HELPERS_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path

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
