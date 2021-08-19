# ---------------------------------------
# install admin
# ---------------------------------------

function bh_install_docker() {
  bh_log_func
  ps_call_admin Enable-WindowsOptionalFeature -Online -FeatureName $("Microsoft-Hyper-V") -All
  ps_call_admin Enable-WindowsOptionalFeature -Online -FeatureName $("Containers") -All
  bh_win_get_install Docker.DockerDesktop
}

function bh_install_tesseract() {
  bh_log_func
  if type tesseract.exe &>/dev/null; then
    bh_win_get_install tesseract
    bh_win_path_add 'C:\Program Files\Tesseract-OCR'
  fi
}

function bh_install_java() {
  bh_log_func
  if type java.exe &>/dev/null; then
    bh_win_get_install ojdkbuild.ojdkbuild
    local javahome=$(ps_call '$(get-command java).Source.replace("\bin\java.exe", "")')
    bh_env_add "JAVA_HOME" "$javahome"
  fi
}

function bh_install_battle_steam() {
  bh_log_func
  bh_win_get_install Blizzard.BattleNet Valve.Steam
}

# ---------------------------------------
# choco helpers
# ---------------------------------------

function bh_choco_install() {
  bh_log_func
  local pkgs_to_install=$(echo $@ | tr ' ' ';')
  gsudo choco install -y --acceptlicense $pkgs_to_install
}

function bh_choco_uninstall() {
  bh_log_func
  local pkgs_to_uninstall=$(echo $@ | tr ' ' ';')
  gsudo choco uninstall -y --acceptlicense $pkgs_to_uninstall
}

function bh_choco_upgrade() {
  bh_log_func
  local outdated=false
  gsudo choco outdated | grep '0 package' >/dev/null || outdated=true
  if $outdated; then gsudo choco upgrade -y --acceptlicense all; fi
}

function bh_choco_list_installed() {
  choco list -l
}

function bh_choco_clean() {
  bh_log_func
  if type choco-cleaner.exe &>/dev/null; then
    gsudo choco install choco-cleaner
  fi
  ps_call 'Invoke-Expression "$env:ChocolateyToolsLocation\BCURRAN3\choco-cleaner.ps1" | Out-Null'
}

# ---------------------------------------
# sysupdate helpers
# ---------------------------------------

function bh_win_sysupdate() {
  bh_log_func
  ps_call_admin '$(Install-WindowsUpdate -AcceptAll -IgnoreReboot) | Where-Object { 
    if ($_ -is [string]) {
      $_.Split("", [System.StringSplitOptions]::RemoveEmptyEntries) 
    } 
  }'
}
function bh_win_sysupdate_list() {
  ps_call_admin 'Get-WindowsUpdate'
}

function bh_win_sysupdate_list_last_installed() {
  ps_call_admin 'Get-WUHistory -Last 10 | Select-Object Date, Title, Result'
}

# ---------------------------------------
# xpulseaudio helpers
# ---------------------------------------

function bh_xpulseaudio_enable() {
  bh_choco_install "pulseaudio vcxsrv"

  # https://wiki.ubuntu.com/WSL#Running_Graphical_Applications
  sudo apt-get install pulseaudio
  echo -e "load-module module-native-protocol-tcp auth-anonymous=1" | sudo "sudo tee -a $(unixpath C:\\ProgramData\\chocolatey\\lib\\pulseaudio\\tools\\etc\\pulse\\default.pa)"
  echo -e "exit-idle-time = -1" | sudo "sudo tee -a $(unixpath C:\\ProgramData\\chocolatey\\lib\\pulseaudio\\tools\\etc\\pulse\\daemon.conf)"

  # configure .profile
  if ! grep -q "PULSE_SERVER" $HOME/.profile; then
    echo -e "\nexport DISPLAY=\"$(awk '/nameserver / {print $2; exit}' /etc/resolv.conf 2>/dev/null):0\"" | tee -a $HOME/.profile
    echo "export PULSE_SERVER=\"$(awk '/nameserver / {print $2; exit}' /etc/resolv.conf 2>/dev/null):0\"" | tee -a $HOME/.profile
    echo "export LIBGL_ALWAYS_INDIRECT=1" | tee -a $HOME/.profile
  fi
}

function bh_xpulseaudio_start() {
  bh_xpulseaudio_stop
  $(unixpath C:\\ProgramData\\chocolatey\\bin\\pulseaudio.exe) &
  "$(unixpath 'C:\Program Files\VcXsrv\vcxsrv.exe')" :0 -multiwindow -clipboard -wgl -ac -silent-dup-error &
}

function bh_xpulseaudio_stop() {
  cmd.exe /c "taskkill /IM pulseaudio.exe /F"
  cmd.exe /c "taskkill /IM vcxsrv.exe /F"
}