#########################
# essetial aliases
#########################

alias powershell='powershell.exe'
alias winget='winget.exe'
alias wsl='wsl.exe'
if [[ -n $WSL_DISTRO_NAME ]]; then
  alias winpath='wslpath -m'
else
  alias winpath='cygpath -m'
fi

#########################
# load scripts as aliases
#########################

for file in "$BH_DIR/scripts/"win_*.ps1; do
  if test -f $file &>/dev/null; then
    script_name=$(basename ${file%.*})
    eval "alias $script_name='powershell.exe $(winpath $file)'"
  fi
done

#########################
# basic
#########################

alias ls='ls --color=auto -I NTUSER\* -I ntuser\* -I AppData -I IntelGraphicsProfiles* -I MicrosoftEdgeBackups'

function win_home_hide_dotfiles() {
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

function win_ssh_add_identity() {
  gsudo powershell.exe -c '
    Set-Service ssh-agent -StartupType Automatic
    Start-Service ssh-agent
    Get-Service ssh-agent
    ssh-add $HOME/.ssh/id_rsa
  '
}

#########################
# start
#########################

function start_startmenu() { powershell.exe -c 'explorer ${env:appdata}\Microsoft\Windows\Start Menu\Programs'; }
function start_startmenu_all_users() { powershell.exe -c 'explorer ${env:programdata}\Microsoft\Windows\Start Menu\Programs'; }
function start_recycle_bin() { powershell.exe -c 'explorer shell:RecycleBinFolder'; }
function start_from_wsl() {
  if ! type wslview &>/dev/null; then sudo apt install wslu; fi
  wslview "$@"
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
  IFS=';' read -ra ADDR <<<"$(win_path_show)"
  for i in "${!ADDR[@]}"; do echo ${ADDR[$i]}; done
}

#########################
# msys2
#########################
alias msys2_start='cmd.exe /mnt/c/msys64/msys2_shell.cmd -defterm -mingw64 -no-start'
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