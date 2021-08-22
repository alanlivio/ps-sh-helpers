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
alias choco='/c/ProgramData/chocolatey/bin/choco.exe'
alias chrome="/c/Program\ Files/Google/Chrome/Application/chrome.exe"
alias whereis='where'
alias reboot='gsudo shutdown \/r'
alias ps_call="powershell -c"
alias ps_call_admin="gsudo powershell -c"

function ps_def_call_as_func() {
  eval "function $1() { ps_call $*; }"
}

function ps_call_script() {
  powershell.exe -command "& { . $1}"
}

function ps_def_script_as_func() {
  eval "function $2() { . $1; }"
}

function bh_ps_test_command() {
  powershell -c '(Get-Command' "$1" '-ea 0) -ne $null'
}
# ---------------------------------------
# load commands
# ---------------------------------------

source "$BH_DIR/win/user.sh" # bh_win_user_check_admin
source "$BH_DIR/win/install.sh"
source "$BH_DIR/win/winget.sh"
source "$BH_DIR/win/explorer.sh"
if type tlshell.exe &>/dev/null; then source "$BH_DIR/win/texlive.sh"; fi

if [ "$(bh_win_user_check_admin)" == "True" ]; then
  source "$BH_DIR/win/install-admin.sh"
  BH_SETUP_MSYS=$(unixpath -w "$BH_DIR/win/setup-msys.ps1")
  BH_SETUP_WSL=$(unixpath -w "$BH_DIR/win/setup-wsl.ps1")
  function bh_win_install_choco() { powershell.exe -command "& { . $BH_INSTALL_CHOCO}"; }
  function bh_setup_wsl() { powershell.exe -command "& { . $BH_SETUP_WSL}"; }
  function bh_setup_msys() { powershell.exe -command "& { . $BH_SETUP_MSYS}"; }
fi

BH_SETUP_WIN=$(unixpath -w "$BH_DIR/win/setup-win.ps1")
function bh_setup_win() { powershell.exe -command "& { . $BH_SETUP_WIN}"; }

function bh_update_clean_win() {
  # windows
  if type gsudo &>/dev/null; then
    bh_win_sysupdate
    bh_win_get_install "$PKGS_WINGET"
    bh_choco_install "$PKGS_CHOCO"
    bh_choco_upgrade
    bh_choco_clean
  fi
  # python
  bh_python_upgrade
  bh_python_install $PKGS_PYTHON
  # vscode
  bh_vscode_install $PKGS_VSCODE
  # cleanup
  bh_home_clean_unused
  bh_explorer_hide_home_dotfiles
}

# ---------------------------------------
# wt helpers
# ---------------------------------------
BH_WT_STGS="$HOME/AppData/Local/Packages/Microsoft.WindowsTerminal_8wekyb3d8bbwe/LocalState/settings.json"

function bh_wt_settings() {
  code $BH_WT_STGS
}
