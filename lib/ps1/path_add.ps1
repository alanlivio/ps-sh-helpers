$addDir = $args[0] 
$addDirEsc = [regex]::Escape($addDir)
$currentPath = [System.Environment]::GetEnvironmentVariable("PATH", "user")
if ([string]::IsNullOrEmpty($currentPath)){
  $newpath = $addDir
} elseif ($currentPath -Match "$addDirEsc\\?"){
  return 
} else{
  $newpath = "$currentPath;$addDir"
}
[System.Environment]::SetEnvironmentVariable("PATH", $newpath, "user")