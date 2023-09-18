param([string] $addDir)

function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }

log_msg "adding to PATH dir: $addDir"
$addDirEsc = [regex]::Escape($addDir)
$currentPath = [System.Environment]::GetEnvironmentVariable("PATH", "user")
if ([string]::IsNullOrEmpty($currentPath)) {
    $newpath = $addDir
}
elseif ($currentPath -Match "$addDirEsc\\?") {
    log_msg "dir already exist in PATH"
    return
}
else {
    $newpath = "$currentPath;$addDir"
}
gsudo [System.Environment]::SetEnvironmentVariable("PATH", $newpath, "user")