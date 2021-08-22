$bh_log_func = 'Write-Host -ForegroundColor DarkYellow "--" $MyInvocation.MyCommand.ToString()'
function bh_log() {
  Write-Host -ForegroundColor DarkYellow "--" ($args -join " ")
}

function bh_env_win_add($name, $value) {
  [System.Environment]::SetEnvironmentVariable("$name", "$value", 'user')
}

function bh_path_win_add($addPath) {
  if (Test-Path $addPath) {
    $currentpath = [System.Environment]::GetEnvironmentVariable('PATH', 'user')
    $regexAddPath = [regex]::Escape($addPath)
    $arrPath = $currentpath -split ';' | Where-Object { $_ -notMatch "^$regexAddPath\\?" }
    $newpath = ($arrPath + $addPath) -join ';'
    bh_env_win_add 'PATH' $newpath
  }
  else {
    Throw "$addPath' is not a valid path."
  }
}

function bh_install_win_python() {
  Invoke-Expression $bh_log_func
  # path depends if your winget settings uses "scope": "user" or "m }hine"
  $py_exe_1 = "${env:UserProfile}\AppData\Local\Programs\Python\Python39\python.exe"
  $py_exe_2 = "C:\Program Files\Python39\python.exe"
  if (!(Test-Path $py_exe_1) -and !(Test-Path $py_exe_2)) {
    winget install Python.Python.3 --scope=user -i
  }
  # Remove windows alias. See https://superuser.com/questions/1437590/typing-python-on-windows-10-version-1903-command-prompt-opens-microsoft-stor
  Remove-Item $env:USERPROFILE\AppData\Local\Microsoft\WindowsApps\python*.exe
  if (Test-Path $py_exe_1) { 
    bh_path_win_add "$(Split-Path $py_exe_1)"
    bh_path_win_add "$(Split-Path $py_exe_1)\Scripts"
  }
  elseif (Test-Path $py_exe_2) {
    bh_path_win_add "$(Split-Path $py_exe_2)" 
    bh_path_win_add "$(Split-Path $py_exe_2)\Scripts"
  }
}
bh_install_win_python