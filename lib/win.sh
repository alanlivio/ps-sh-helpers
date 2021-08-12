#!/bin/bash

# ---------------------------------------
# alias for path
# ---------------------------------------

if $IS_WINDOWS_WSL; then
  # fix writting permissions
  if [[ "$(umask)" = "0000" ]]; then
    umask 0022
  fi
  alias unixpath='wslpath'
  alias winpath='wslpath -w'
elif $IS_WINDOWS; then
  alias unixpath='cygpath'
  alias winpath='cygpath -w'
  # fix mingw tmp
  unset temp
  unset tmp
fi

SCRIPT_PS_WPATH=$(unixpath -w "$SCRIPT_DIR/helpers.ps1")

# ---------------------------------------
# alias for others
# ---------------------------------------

# hide windows user files when ls home
alias ls='ls --color=auto --hide=ntuser* --hide=NTUSER* --hide=AppData --hide=IntelGraphicsProfiles* --hide=MicrosoftEdgeBackups'
alias start="cmd.exe /c start"
alias choco='/c/ProgramData/chocolatey/bin/choco.exe'
alias chrome="/c/Program\ Files/Google/Chrome/Application/chrome.exe"
if $IS_WINDOWS_GITBASH; then
  alias whereis='where'
  alias reboot='gsudo shutdown \/r'
  alias sudo='gsudo'
fi

# ---------------------------------------
# ps funcs
# ---------------------------------------

function hf_ps_call() {
  powershell.exe -command "& { . $SCRIPT_PS_WPATH; $* }"
}

function hf_ps_call_admin() {
  sudo powershell.exe -command "& { . $SCRIPT_PS_WPATH;  $* }"
}

function hf_ps_def_func() {
  eval "function $1() { hf_ps_call $*; }"
}

function hf_ps_def_func_admin() {
  eval "function $1()"'{ echo $*; hf_ps_call_admin '"$1"' $*; }'
}

function hf_ps_test_command() {
  powershell -c '(Get-Command' "$1" '-ea 0) -ne $null'
}

# ---------------------------------------
# path
# ---------------------------------------

function hf_path() {
  echo "$PATH"
}

function hf_path_add() {
  local dir=$(winpath $1)
  hf_ps_call "hf_path_add $dir"
}
# ---------------------------------------
# setup funcs
# ---------------------------------------

function hf_setup_wsl() {
  # sudo nopasswd
  hf_user_permissions_sudo_nopasswd
  # essentials
  PKGS="git deborphan apt-file $PKGS_ESSENTIALS "
  # python
  PKGS+="python3-pip "
  hf_apt_install $PKGS
  # set python3 as default
  hf_python_set_python3_default
}

hf_ps_def_func_admin hf_setup_windows

# ---------------------------------------
# choco funcs
# ---------------------------------------

# choco funcs from helpers.ps1
hf_ps_def_func_admin hf_choco_install
hf_ps_def_func_admin hf_choco_uninstall
hf_ps_def_func_admin hf_choco_list_installed
hf_ps_def_func_admin hf_choco_clean
hf_ps_def_func_admin hf_choco_delete_local_lib

# ---------------------------------------
# winget funcs
# ---------------------------------------

# winget funcs from helpers.ps1
hf_ps_def_func_admin hf_winget_install
hf_ps_def_func_admin hf_winget_uninstall
hf_ps_def_func_admin hf_winget_upgrade
hf_ps_def_func hf_winget_settings

# ---------------------------------------
# ouside wsl funcs
# ---------------------------------------

hf_ps_def_func_admin hf_wsl_terminate
hf_ps_def_func_admin hf_wsl_list
hf_ps_def_func_admin hf_wsl_get_default

# ---------------------------------------
# env
# ---------------------------------------

hf_ps_def_func_admin hf_env_add

# ---------------------------------------
# wt funcs
# ---------------------------------------

# wt funcs from helpers.ps1
hf_ps_def_func hf_wt_settings

# ---------------------------------------
# install funcs
# ---------------------------------------

if $IS_WINDOWS_GITBASH; then
  HF_FLUTTER_VER="2.2.3"

  function hf_install_windows_androidcmd_flutter() {
    hf_log_func

    # create opt
    local OPT_DST="$HELPERS_OPT_WIN/"
    hf_test_and_create_folder $OPT_DST

    # android cmd and sdk
    local ANDROID_SDK_DIR="$OPT_DST/android"
    local ANDROID_CMD_DIR="$ANDROID_SDK_DIR/cmdline-tools"
    local ANDROID_CMD_URL="https://dl.google.com/android/repository/commandlinetools-win-6858069_latest.zip"
    if ! test -d $ANDROID_CMD_DIR; then
      hf_wget_extract $ANDROID_CMD_URL $ANDROID_SDK_DIR
      if test $? != 0; then hf_log_error "wget failed." && return 1; fi
      hf_ps_call_admin "hf_path_add $(winpath $ANDROID_CMD_DIR/bin)"
    fi
    if ! test -d $ANDROID_SDK_DIR/platforms; then
      $ANDROID_CMD_DIR/bin/sdkmanager.bat --sdk_root="$ANDROID_SDK_DIR" --install 'platform-tools' 'platforms;android-29'
      yes | $ANDROID_CMD_DIR/bin/sdkmanager.bat --sdk_root="$ANDROID_SDK_DIR" --licenses
      hf_ps_call_admin "hf_env_add ANDROID_HOME $(winpath $ANDROID_SDK_DIR)"
      hf_ps_call_admin "hf_env_add ANDROID_SDK_ROOT $(winpath $ANDROID_SDK_DIR)"
      hf_ps_call_admin "hf_path_add $(winpath $ANDROID_SDK_DIR/platform-tools)"
    fi

    # flutter
    local FLUTTER_SDK_DIR="$OPT_DST/flutter"
    local FLUTTER_SDK_URL="https://storage.googleapis.com/flutter_infra_release/releases/stable/windows/flutter_windows_${HF_FLUTTER_VER}-stable.zip"
    if ! test -d $FLUTTER_SDK_DIR; then
      # OPT_DST beacuase zip extract the flutter dir
      hf_wget_extract $FLUTTER_SDK_URL $OPT_DST
      if test $? != 0; then hf_log_error "wget failed." && return 1; fi
      hf_ps_call_admin "hf_path_add $(winpath $FLUTTER_SDK_DIR/bin)"
    fi
  }

  function hf_install_windows_latexindent() {
    hf_log_func
    if ! type latexindent.exe &>/dev/null; then
      wget https://github.com/cmhughes/latexindent.pl/releases/download/V3.10/latexindent.exe -P /c/tools/
      wget https://raw.githubusercontent.com/cmhughes/latexindent.pl/main/defaultSettings.yaml -P /c/tools/
    fi
  }
fi

function hf_install_texlive() {
  sudo choco install texlive
}

# ---------------------------------------
# update funcs
# ---------------------------------------

function hf_update_clean_windows() {
  # windows
  hf_ps_call_admin "hf_windows_update"
  hf_ps_call_admin "hf_winget_install $PKGS_WINGET"
  hf_ps_call_admin "hf_appx_install $PKGS_APPX"
  hf_ps_call_admin "hf_choco_install $PKGS_CHOCO"
  hf_ps_call_admin "hf_choco_upgrade"
  hf_ps_call_admin "hf_choco_clean"
  # if WSL
  if $IS_WINDOWS_WSL; then
    # apt
    hf_apt_upgrade
    hf_apt_install $PKGS_APT
    hf_apt_autoremove
    hf_apt_remove_pkgs $PKGS_REMOVE_APT
    hf_apt_remove_orphan_pkgs $PKGS_APT_ORPHAN_EXPECTIONS
  fi
  # python
  # python pkgs in msys require be builded from msys
  if $IS_WINDOWS_MSYS; then
    hf_msys_install $PKGS_PYTHON_MSYS
  elif $IS_WINDOWS_GITBASH; then
    hf_python_upgrade
    hf_python_install $PKGS_PYTHON
  fi
  # vscode
  hf_vscode_install $PKGS_VSCODE
  # cleanup
  hf_home_clean_unused_dirs
  hf_ps_call hf_home_hide_dotfiles
  hf_ps_call hf_explorer_clean_unused_shortcuts
}
