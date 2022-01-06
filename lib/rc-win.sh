#!/bin/bash

# ---------------------------------------
# gitbash aliases
# ---------------------------------------

alias unixpath='cygpath'
alias winpath='cygpath -w'
# fix mingw tmp
unset temp
unset tmp
# hide windows user files when ls home
alias ls='ls --color=auto --hide=ntuser* --hide=NTUSER* --hide=AppData --hide=IntelGraphicsProfiles* --hide=MicrosoftEdgeBackups'
alias chrome="/c/Program\ Files/Google/Chrome/Application/chrome.exe"
alias whereis='where'
alias reboot='gsudo shutdown \/r'
alias ps_call="powershell.exe -c"
alias ps_call_admin="gsudo powershell.exe -c"
alias ghostscript='gswin64c'

function bh_win_gitbash_fix_prompt {
  sed '/show\sMSYSTEM/d' -i /etc/profile.d/git-prompt.sh
}

function bh_open {
  local node="${1:-.}" # . is default value
  ps_call "Start-Process $node"
}

function bh_open_wt_settings() {
  bh_wt_stgs="$HOME/AppData/Local/Packages/Microsoft.WindowsTerminal_8wekyb3d8bbwe/LocalState/settings.json"
  code $bh_wt_stgs
}

function ps_call_script() {
  powershell.exe -c "& { . $1}"
}

function ps_call_script_admin() {
  gsudo powershell.exe -c "& { . $1}"
}

# ---------------------------------------
# user
# ---------------------------------------

# usage if [ "$(bh_win_user_check_admin)" == "True" ]; then <commands>; fi
function bh_win_user_check_admin() {
  ps_call '
    $user = "$env:COMPUTERNAME\$env:USERNAME"
    $group = "Administrators"
    (Get-LocalGroupMember $group).Name -contains $user
  '
}

function bh_win_user_check_eleveated_shell() {
  ps_call '(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)' | tr -d '\rn'
}

# ---------------------------------------
# env
# ---------------------------------------

function bh_win_env_show() {
  ps_call 'Get-ChildItem Env:'
}

function bh_win_env_add() {
  : ${2?"Usage: ${FUNCNAME[0]} <varname> <value>"}
  ps_call "[System.Environment]::SetEnvironmentVariable('$1', '$2', 'user')"
}

# ---------------------------------------
# path
# ---------------------------------------

function bh_win_path_show() {
  ps_call '(Get-ChildItem Env:Path).Value'
}

function bh_win_path_show_as_list() {
  IFS=';' read -ra ADDR <<<$(bh_win_path_show)
  for i in "${!ADDR[@]}"; do echo ${ADDR[$i]}; done
}

function bh_win_path_add() {
  local dir=$(winpath $@)
  ps_call ' 
    function bh_win_path_add($addDir) {
      $currentpath = [System.Environment]::GetEnvironmentVariable("PATH", "user")
      $regexAddPath = [regex]::Escape($addDir)
      $arrPath = $currentpath -split ";" | Sort-Object -Unique | Where-Object { $_ -notMatch "^$regexAddPath\\?" }
      $newpath = ($arrPath + $addDir) -join ";"
      [System.Environment]::SetEnvironmentVariable("PATH", $newpath, "user")
    }; bh_win_path_add ' \"$dir\"
}

function bh_win_path_remove() {
  local dir=$(winpath $@)
  ps_call ' 
    function bh_win_path_remove($remDir) {
      $currentpath = [System.Environment]::GetEnvironmentVariable("PATH", "user")
      $newpath = ($currentpath.Split(";") | Where-Object { $_ -ne "$remDir" }) -join ";"
      [System.Environment]::SetEnvironmentVariable("PATH", $newpath, "user")
    }; bh_win_path_remove ' \"$dir\"
}

function bh_win_path_add_winapps() {
  bh_win_path_add "$HOME/AppData/Local/Microsoft/WindowsApps/"
}

function bh_win_path_open_settings() {
  rundll32 sysdm.cpl,EditEnvironmentVariables &
}

# ---------------------------------------
# load commands
# ---------------------------------------

if type gsudo &>/dev/null; then source "$BH_DIR/lib/win/admin.sh"; fi
source "$BH_DIR/lib/win/explorer.sh"
source "$BH_DIR/lib/win/install.sh"
source "$BH_DIR/lib/win/winget.sh"

function bh_win_sanity() {
  powershell.exe -command "& { . $(unixpath -w $BH_DIR/lib/win/win-sanity.ps1) }"
}

# ---------------------------------------
# update_clean
# ---------------------------------------

function bh_update_cleanup_win() {
  # cleanup
  bh_home_clean_unused
  bh_win_explorer_hide_home_dotfiles
  # python
  type pip &>/dev/null && bh_python_install $BH_PKGS_PYTHON
  # vscode
  type code &>/dev/null && bh_vscode_install $BH_PKGS_VSCODE
  # windows
  type gsudo &>/dev/null && bh_win_sysupdate_win
  # winget (it uses --scope=user)
  bh_win_get_install $BH_PKGS_WINGET
}
