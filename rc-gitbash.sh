#!/bin/bash

# ---------------------------------------
# var/alias
# ---------------------------------------

alias unixpath='cygpath'
alias winpath='cygpath -w'
# fix mingw tmp
unset temp
unset tmp
# hide windows user files when ls home
alias ls='ls --color=auto --hide=ntuser* --hide=NTUSER* --hide=AppData --hide=IntelGraphicsProfiles* --hide=MicrosoftEdgeBackups'
alias start="cmd.exe /c start"
alias chrome="/c/Program\ Files/Google/Chrome/Application/chrome.exe"
alias whereis='where'
alias reboot='gsudo shutdown \/r'
alias ps_call="powershell.exe -c"
alias ps_call_admin="gsudo powershell.exe -c"

function ps_call_script() {
  powershell.exe -command "& { . $1}"
}

function ps_call_script_admin() {
  gsudo powershell.exe -command "& { . $1}"
}

# ---------------------------------------
# load commands
# ---------------------------------------

source "$BH_DIR/win/user.sh" # bh_user_win_check_admin
source "$BH_DIR/win/install.sh"
source "$BH_DIR/win/winget.sh"
source "$BH_DIR/win/explorer.sh"
if type tlshell.exe &>/dev/null; then source "$BH_DIR/win/texlive.sh"; fi

if [ "$(bh_user_win_check_admin)" == "True" ]; then
  source "$BH_DIR/win/admin.sh"
fi

function bh_win_sanity() {
  powershell.exe -command "& { . $(unixpath -w $BH_DIR/win/win-sanity.ps1) }"
}

function bh_update_clean_win() {
  # windows
  if [ "$(bh_user_win_check_admin)" == "True" ]; then
    bh_syswin_update_win
  fi
  # winget (it uses --scope=user)
  bh_winget_install $BH_PKGS_WINGET
  # python
  bh_install_python
  bh_python_upgrade
  bh_python_install $BH_PKGS_PYTHON
  # vscode
  bh_install_win_vscode
  bh_vscode_install $BH_PKGS_VSCODE
  # cleanup
  bh_home_clean_unused
  bh_explorer_hide_home_dotfiles
}

# ---------------------------------------
# wt
# ---------------------------------------
BH_WT_STGS="$HOME/AppData/Local/Packages/Microsoft.WindowsTerminal_8wekyb3d8bbwe/LocalState/settings.json"

function bh_wt_settings() {
  code $BH_WT_STGS
}
