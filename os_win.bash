#########################
# basic
#########################

alias ls='ls --color=auto -I NTUSER\* -I ntuser\* -I AppData -I IntelGraphicsProfiles* -I MicrosoftEdgeBackups'
alias winget='winget.exe'
alias powershell='powershell.exe'
BH_LIB_PS1="$BH_DIR/lib/ps1/"

function home_win_hide_files() {
  powershell -c 'Get-ChildItem "${env:userprofile}\\.*" | ForEach-Object { $_.Attributes += "Hidden" }'
  if [ -n "$BH_WIN_HIDE_HOME" ]; then
    local to_hide=$(printf '"%s"' "${BH_WIN_HIDE_HOME[@]}" | sed 's/""/","/g')
    powershell -c '
      $list =' "$to_hide" '
      $nodes = Get-ChildItem ${env:userprofile} | Where-Object {$_.name -In $list}
      $nodes | ForEach-Object { $_.Attributes += "Hidden" }
    '
  fi
}

function win_update() {
  winget upgrade --all --silent
  gsudo powershell.exe -c 'Install-Module -Name PSWindowsUpdate -Force; Install-WindowsUpdate -AcceptAll -IgnoreReboot'
}

#########################
# start
#########################

function start_startmenu() { powershell -c 'explorer ${env:appdata}\Microsoft\Windows\Start Menu\Programs'; }
function start_startmenu_all_users() { powershell -c 'explorer ${env:programdata}\Microsoft\Windows\Start Menu\Programs'; }
function start_recycle_bin() { powershell -c 'explorer shell:RecycleBinFolder'; }
function start_from_wsl(){
  if ! type wslview &>/dev/null; then sudo apt install wslu; fi
  wslu $@
}

#########################
# win sanity
#########################

function win_sanity_password_policy() { gsudo powershell.exe \'$(winpath $BH_LIB_PS1/sanity_password_policy.ps1)\'; }
function win_sanity_explorer() { gsudo powershell.exe \'$(winpath $BH_LIB_PS1/sanity_explorer.ps1)\'; }
function win_sanity_ui() { gsudo powershell.exe \'$(winpath $BH_LIB_PS1/sanity_ui.ps1)\'; }
function win_sanity_services_apps() { gsudo powershell.exe \'$(winpath $BH_LIB_PS1/sanity_unused_services.ps1)\'; }

#########################
# regedit
#########################

function regedit_open_path() {
  powershell -c "
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
  powershell -c '[System.Environment]::GetEnvironmentVariables()'
}

function win_env_add() {
  : ${2?"Usage: ${FUNCNAME[0]} <varname> <value>"}
  powershell -c "[System.Environment]::SetEnvironmentVariable('$1', '$2', 'user')"
}

function win_path_show() {
  powershell -c '(Get-ChildItem Env:Path).Value'
}

function win_path_show_as_list() {
  IFS=';' read -ra ADDR <<<$(win_path_show)
  for i in "${!ADDR[@]}"; do echo ${ADDR[$i]}; done
}

function win_path_add() { # using ps1 script
  local dir=$(winpath $@)
  local dircyg=$(cygpath $@)
  # export in win
  powershell -c "$(winpath $BH_LIB_PS1/path_add.ps1)" \'$dir\'
  # export in bash (it will reolad from win in new shell)
  if [[ ":$PATH:" != *":$dircyg:"* ]]; then export PATH=${PATH}:$dircyg; fi
}

#########################
# winget
#########################

function winget_install() {
  local pkgs_to_install=""
  for i in "$@"; do
    if [[ $(winget list --id $i) =~ "No installed"* ]]; then
      pkgs_to_install="$i $pkgs_to_install"
    fi
  done
  if test ! -z "$pkgs_to_install"; then
    echo "pkgs_to_install=$pkgs_to_install"
    for pkg in $pkgs_to_install; do
      winget install --accept-package-agreements --accept-source-agreements --silent $pkg
    done
  fi
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
fi

#########################
# wsl
#########################

function wsl_use_same_home() { gsudo powershell.exe \'$(winpath $BH_LIB_PS1/wsl_use_same_home.ps1)\'; }
function wsl_code_from_win() {
  if [ "$#" -ne 0 ]; then
    powershell -c '& code ' "$@"
  else
    powershell -c '& code .'
  fi
}
