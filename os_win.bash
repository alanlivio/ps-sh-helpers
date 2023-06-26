#########################
# basic
#########################

alias ls='ls --color=auto -I NTUSER\* -I ntuser\* -I AppData -I IntelGraphicsProfiles* -I MicrosoftEdgeBackups'
BH_LIB_PS1="$BH_DIR/scripts/"

function home_clean_win() {
  if [[ -n $WSL_DISTRO_NAME ]]; then
    home_clean $(wslpath $(wslvar USERPROFILE))
  else
    home_clean
  fi
  # set Hidden to nodes .*
  powershell.exe -c 'Get-ChildItem "${env:userprofile}\\.*" | ForEach-Object { $_.Attributes += "Hidden" }'
  # set Hidden to nodes defined $BH_WIN_HIDE_HOME
  if [ -n "$BH_WIN_HIDE_HOME" ]; then
    local to_hide=$(printf '"%s"' "${BH_WIN_HIDE_HOME[@]}" | sed 's/""/","/g')
    powershell.exe -c '
      $list =' "$to_hide" '
      $nodes = Get-ChildItem ${env:userprofile} | Where-Object {$_.name -In $list}
      $nodes | ForEach-Object { $_.Attributes += "Hidden" }
    '
  fi
}

function winget_install() {
  local pkgs_to_install=""
  for i in "$@"; do
    if [[ $(winget.exe list --id $i) =~ "No installed"* ]]; then
      pkgs_to_install="$i $pkgs_to_install"
    fi
  done
  if test ! -z "$pkgs_to_install"; then
    for pkg in $pkgs_to_install; do
      winget.exe install --accept-package-agreements --accept-source-agreements --silent $pkg
    done
  fi
}

function win_update() {
  if type winget.exe &>/dev/null && test -n "$BH_PKGS_WINGET"; then
    log_msg "winget check installed BH_PKGS_WINGET: $BH_PKGS_WINGET"
    winget_install $BH_PKGS_WINGET
    log_msg "winget upgrade all"
    winget.exe upgrade --all --silent
  fi
  log_msg "win os upgrade"
  gsudo powershell.exe -c 'Install-Module -Name PSWindowsUpdate -Force; Install-WindowsUpdate -AcceptAll -IgnoreReboot'
}

#########################
# start
#########################

function start_startmenu() { powershell.exe -c 'explorer ${env:appdata}\Microsoft\Windows\Start Menu\Programs'; }
function start_startmenu_all_users() { powershell.exe -c 'explorer ${env:programdata}\Microsoft\Windows\Start Menu\Programs'; }
function start_recycle_bin() { powershell.exe -c 'explorer shell:RecycleBinFolder'; }
function start_from_wsl() {
  if ! type wslview &>/dev/null; then sudo apt install wslu; fi
  wslview $@
}

#########################
# regedit
#########################

function regedit_open_path() {
  powershell.exe -c "
    reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\ /v Lastkey /d 'Computer\\$1' /t REG_SZ /f
    regedit.exe
  "
}

function regedit_open_shell_folders() {
  regedit_open_path 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
}

#########################
# env & path
#########################

function win_env_show() {
  powershell.exe -c '[System.Environment]::GetEnvironmentVariables()'
}

function win_env_add() {
  : ${2?"Usage: ${FUNCNAME[0]} <varname> <value>"}
  powershell.exe -c "[System.Environment]::SetEnvironmentVariable('$1', '$2', 'user')"
}

function win_path_show() {
  powershell.exe -c '(Get-ChildItem Env:Path).Value'
}

function win_path_show_as_list() {
  IFS=';' read -ra ADDR <<<$(win_path_show)
  for i in "${!ADDR[@]}"; do echo ${ADDR[$i]}; done
}

function win_path_add() { # using ps1 script
  local dir=$(winpath $@)
  local dircyg=$(cygpath $@)
  # export in win
  powershell.exe -c "$(winpath $BH_LIB_PS1/win_path_add.ps1)" \'$dir\'
  # export in bash (it will reolad from win in new shell)
  if [[ ":$PATH:" != *":$dircyg:"* ]]; then export PATH=${PATH}:$dircyg; fi
}

#########################
# msys2
#########################
if type pacman &>/dev/null; then
  alias msys2_search='pacman -s --noconfirm'
  alias msys2_show='pacman -Qi'
  alias msys2_list_installed='pacman -Qqe'
  alias msys2_install='pacman -S --noconfirm'
  alias msys2_uninstall='pacman -R --noconfirm'
  alias msys2_use_same_home='echo db_home: windows >>/etc/nsswitch.conf'
  function msys2_update() {
    if test -n "$BH_PKGS_MSYS2"; then
      log_msg "msys2 check installed BH_PKGS_MSYS2: $BH_PKGS_MSYS2"
      pacman -S --noconfirm $BH_PKGS_MSYS2
    fi
    log_msg "msys2 upgrade all"
    pacman -Suy
  }
fi

#########################
# sanity/disable/enable
#########################

function win_policy_reset() {
  gsudo cmd.exe /C 'RD /S /Q %WinDir%\\System32\\GroupPolicyUsers '
  gsudo cmd.exe /C 'RD /S /Q %WinDir%\System32\GroupPolicy '
  gsudo gpupdate.exe /force
}

function ps1_script() { powershell.exe "$(winpath $BH_LIB_PS1/$1)"; }
function win_disable_apps_preinstalled() { ps1_script win_disable_apps_preinstalled.ps1; }
function win_disable_hotkeys() { ps1_script win_disable_hotkeys.ps1; }
function win_disable_password_policy() { ps1_script win_disable_password_policy.ps1; }
function win_disable_pc_folders() { ps1_script win_disable_pc_folders.ps1; }
function win_disable_sounds() { ps1_script win_disable_sounds.ps1; }
function win_enable_hyper_v() { ps1_script win_enable_hyper_v.ps1; }
function win_path_add() { ps1_script win_path_add.ps1; }
