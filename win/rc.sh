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
# load libs for specific commands
# ---------------------------------------

source "$BH_DIR/win/user.sh" # bh_win_user_check_admin
if type tlshell.exe &>/dev/null; then source "$BH_DIR/win/texlive.sh"; fi
if type wsl.exe &>/dev/null; then source "$BH_DIR/win/wsl.sh"; fi
if type gsudo &>/dev/null; then source "$BH_DIR/win/admin.sh"; fi
source "$BH_DIR/win/winget.sh"
source "$BH_DIR/win/explorer.sh"

# ---------------------------------------
# load scripts as funcs
# ---------------------------------------

BH_INSTALL_CHOCO=$(unixpath -w "$BH_DIR/win/install-choco.ps1")
BH_SETUP_MSYS=$(unixpath -w "$BH_DIR/win/setup-msys.ps1")
BH_SETUP_WSL=$(unixpath -w "$BH_DIR/win/setup-wsl.ps1")
BH_SETUP_WIN=$(unixpath -w "$BH_DIR/win/setup-win.ps1")
function bh_win_install_choco() { powershell.exe -command "& { . $BH_INSTALL_CHOCO}"; }
function bh_setup_wsl() { powershell.exe -command "& { . $BH_SETUP_WSL}"; }
function bh_setup_msys() { powershell.exe -command "& { . $BH_SETUP_MSYS}"; }
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
# ---------------------------------------
# install non-admin
# ---------------------------------------

BH_FLUTTER_VER="2.2.3"
BH_ANDROID_CMD_VER="7583922"

function bh_win_install_androidcmd_flutter() {
  bh_log_func

  # create opt
  local opt_dst="$BH_OPT_WIN"
  bh_test_and_create_folder $opt_dst

  # android cmd and sdk
  local android_sdk_dir="$opt_dst/android"
  local android_cmd_dir="$android_sdk_dir/cmdline-tools"
  local android_cmd_url="https://dl.google.com/android/repository/commandlinetools-win-${BH_ANDROID_CMD_VER}_latest.zip"
  if ! test -d $android_cmd_dir; then
    bh_decompress_from_url $android_cmd_url $android_sdk_dir
    if test $? != 0; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
    bh_win_path_add $(winpath $android_cmd_dir/bin)
  fi
  if ! test -d $android_sdk_dir/platforms; then
    $android_cmd_dir/bin/sdkmanager.bat --sdk_root="$android_sdk_dir" --install 'platform-tools' 'platforms;android-29'
    yes | $android_cmd_dir/bin/sdkmanager.bat --sdk_root="$android_sdk_dir" --licenses
    bh_win_env_add ANDROID_HOME $(winpath $android_sdk_dir)
    bh_win_env_add ANDROID_SDK_ROOT $(winpath $android_sdk_dir)
    bh_win_path_add $(winpath $android_sdk_dir/platform-tools)
  fi

  # flutter
  local flutter_sdk_dir="$opt_dst/flutter"
  local flutter_sdk_url="https://storage.googleapis.com/flutter_infra_release/releases/stable/windows/flutter_windows_${BH_FLUTTER_VER}-stable.zip"
  if ! test -d $flutter_sdk_dir; then
    # opt_dst beacuase zip extract the flutter dir
    bh_decompress_from_url $flutter_sdk_url $opt_dst
    if test $? != 0; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
    bh_win_path_add $(winpath $flutter_sdk_dir/bin)
  fi
}

function bh_win_install_latexindent() {
  bh_log_func
  if ! type latexindent.exe &>/dev/null; then
    bh_curl_fetch_to_dir https://github.com/cmhughes/latexindent.pl/releases/download/V3.10/latexindent.exe $BH_OPT_WIN/
    bh_curl_fetch_to_dir https://raw.githubusercontent.com/cmhughes/latexindent.pl/main/defaultSettings.yaml $BH_OPT_WIN/
  fi
}
