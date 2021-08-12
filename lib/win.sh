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

SCRIPT_PS_WPATH=$(unixpath -w "$SCRIPT_DIR/rc.ps1")

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
# ps helpers
# ---------------------------------------

function bh_ps_call() {
  powershell.exe -command "& { . $SCRIPT_PS_WPATH; $* }"
}

function bh_ps_call_admin() {
  sudo powershell.exe -command "& { . $SCRIPT_PS_WPATH;  $* }"
}

function bh_ps_def_func() {
  eval "function $1() { bh_ps_call $*; }"
}

function bh_ps_def_func_admin() {
  eval "function $1()"'{ echo $*; bh_ps_call_admin '"$1"' $*; }'
}

function bh_ps_test_command() {
  powershell -c '(Get-Command' "$1" '-ea 0) -ne $null'
}

# ---------------------------------------
# path helpers
# ---------------------------------------

function bh_path() {
  echo "$PATH"
}

function bh_path_add() {
  local dir=$(winpath $1)
  bh_ps_call "bh_path_add $dir"
}
# ---------------------------------------
# setup helpers
# ---------------------------------------

function bh_setup_wsl() {
  # sudo nopasswd
  bh_user_permissions_sudo_nopasswd
  # essentials
  PKGS="git deborphan apt-file $PKGS_ESSENTIALS "
  # python
  PKGS+="python3-pip "
  bh_apt_install $PKGS
  # set python3 as default
  bh_python_set_python3_default
}

bh_ps_def_func_admin bh_setup_windows

# ---------------------------------------
# choco helpers
# ---------------------------------------

# choco helpers from rc.ps1
bh_ps_def_func_admin bh_choco_install
bh_ps_def_func_admin bh_choco_uninstall
bh_ps_def_func_admin bh_choco_list_installed
bh_ps_def_func_admin bh_choco_clean
bh_ps_def_func_admin bh_choco_delete_local_lib

# ---------------------------------------
# winget helpers
# ---------------------------------------

# winget helpers from rc.ps1
bh_ps_def_func_admin bh_winget_install
bh_ps_def_func_admin bh_winget_uninstall
bh_ps_def_func_admin bh_winget_upgrade
bh_ps_def_func bh_winget_settings

# ---------------------------------------
# outside wsl helpers
# ---------------------------------------

bh_ps_def_func_admin bh_wsl_terminate
bh_ps_def_func_admin bh_wsl_list
bh_ps_def_func_admin bh_wsl_get_default

# ---------------------------------------
# env helpers
# ---------------------------------------

bh_ps_def_func_admin bh_env_add

# ---------------------------------------
# wt helpers
# ---------------------------------------

# wt helpers from rc.ps1
bh_ps_def_func bh_wt_settings

# ---------------------------------------
# install helpers
# ---------------------------------------

if $IS_WINDOWS_GITBASH; then
  BH_FLUTTER_VER="2.2.3"

  function bh_install_windows_androidcmd_flutter() {
    bh_log_func

    # create opt
    local OPT_DST="$HELPERS_OPT_WIN/"
    bh_test_and_create_folder $OPT_DST

    # android cmd and sdk
    local ANDROID_SDK_DIR="$OPT_DST/android"
    local ANDROID_CMD_DIR="$ANDROID_SDK_DIR/cmdline-tools"
    local ANDROID_CMD_URL="https://dl.google.com/android/repository/commandlinetools-win-6858069_latest.zip"
    if ! test -d $ANDROID_CMD_DIR; then
      bh_wget_extract $ANDROID_CMD_URL $ANDROID_SDK_DIR
      if test $? != 0; then bh_log_error "wget failed." && return 1; fi
      bh_ps_call_admin "bh_path_add $(winpath $ANDROID_CMD_DIR/bin)"
    fi
    if ! test -d $ANDROID_SDK_DIR/platforms; then
      $ANDROID_CMD_DIR/bin/sdkmanager.bat --sdk_root="$ANDROID_SDK_DIR" --install 'platform-tools' 'platforms;android-29'
      yes | $ANDROID_CMD_DIR/bin/sdkmanager.bat --sdk_root="$ANDROID_SDK_DIR" --licenses
      bh_ps_call_admin "bh_env_add ANDROID_HOME $(winpath $ANDROID_SDK_DIR)"
      bh_ps_call_admin "bh_env_add ANDROID_SDK_ROOT $(winpath $ANDROID_SDK_DIR)"
      bh_ps_call_admin "bh_path_add $(winpath $ANDROID_SDK_DIR/platform-tools)"
    fi

    # flutter
    local FLUTTER_SDK_DIR="$OPT_DST/flutter"
    local FLUTTER_SDK_URL="https://storage.googleapis.com/flutter_infra_release/releases/stable/windows/flutter_windows_${BH_FLUTTER_VER}-stable.zip"
    if ! test -d $FLUTTER_SDK_DIR; then
      # OPT_DST beacuase zip extract the flutter dir
      bh_wget_extract $FLUTTER_SDK_URL $OPT_DST
      if test $? != 0; then bh_log_error "wget failed." && return 1; fi
      bh_ps_call_admin "bh_path_add $(winpath $FLUTTER_SDK_DIR/bin)"
    fi
  }

  function bh_install_windows_latexindent() {
    bh_log_func
    if ! type latexindent.exe &>/dev/null; then
      wget https://github.com/cmhughes/latexindent.pl/releases/download/V3.10/latexindent.exe -P /c/tools/
      wget https://raw.githubusercontent.com/cmhughes/latexindent.pl/main/defaultSettings.yaml -P /c/tools/
    fi
  }
fi

function bh_install_texlive() {
  sudo choco install texlive
}

# ---------------------------------------
# update helpers
# ---------------------------------------

function bh_update_clean_windows() {
  # windows
  bh_ps_call_admin "bh_windows_update"
  bh_ps_call_admin "bh_winget_install $PKGS_WINGET"
  bh_ps_call_admin "bh_appx_install $PKGS_APPX"
  bh_ps_call_admin "bh_choco_install $PKGS_CHOCO"
  bh_ps_call_admin "bh_choco_upgrade"
  bh_ps_call_admin "bh_choco_clean"
  # if WSL
  if $IS_WINDOWS_WSL; then
    # apt
    bh_apt_upgrade
    bh_apt_install $PKGS_APT
    bh_apt_autoremove
    bh_apt_remove_pkgs $PKGS_REMOVE_APT
    bh_apt_remove_orphan_pkgs $PKGS_APT_ORPHAN_EXPECTIONS
  fi
  # python
  # python pkgs in msys require be builded from msys
  if $IS_WINDOWS_MSYS; then
    bh_msys_install $PKGS_PYTHON_MSYS
  elif $IS_WINDOWS_GITBASH; then
    bh_python_upgrade
    bh_python_install $PKGS_PYTHON
  fi
  # vscode
  bh_vscode_install $PKGS_VSCODE
  # cleanup
  bh_home_clean_unused_dirs
  bh_ps_call bh_home_hide_dotfiles
  bh_ps_call bh_explorer_clean_unused_shortcuts
}
