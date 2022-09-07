param([string]$addDir)

function log() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }

log "adding to PATH ... $addDir"
$addDirEsc = [regex]::Escape($addDir)
$currentPath = [System.Environment]::GetEnvironmentVariable("PATH", "user")
if ([string]::IsNullOrEmpty($currentPath)) {
  $newpath = $addDir
}
elseif ($currentPath -Match "$addDirEsc\\?") {
  return 
}
else {
  $newpath = "$currentPath;$addDir"
}
[System.Environment]::SetEnvironmentVariable("PATH", $newpath, "user")