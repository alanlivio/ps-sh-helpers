#!/bin/bash

# ---------------------------------------
# OS vars
# ---------------------------------------

IS_MAC=false
IS_LINUX=false
IS_LINUX_UBUNTU=false
IS_WINDOWS=false
IS_WINDOWS_WSL=false
IS_WINDOWS_MSYS=false
IS_WINDOWS_GITBASH=false

case "$(uname -s)" in
CYGWIN* | MINGW* | MSYS*)
  IS_WINDOWS=true
  if type pacman &>/dev/null; then
    IS_WINDOWS_MSYS=true
  else
    IS_WINDOWS_GITBASH=true
  fi
  ;;
Linux)
  if [[ $(uname -r) == *"icrosoft"* ]]; then
    IS_WINDOWS=true
    IS_WINDOWS_WSL=true
  elif [[ $(lsb_release -d | awk '{print $2}') == Ubuntu ]]; then
    IS_LINUX=true
    IS_LINUX_UBUNTU=true
  fi
  ;;
Darwin)
  IS_MAC=true
  ;;
esac

# ---------------------------------------
# helpers vars
# ---------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="$SCRIPT_DIR/helpers.sh"
DOTFILES_VSCODE="$SCRIPT_DIR/skel/vscode"
PKGS_ESSENTIALS="vim diffutils curl wget "

# if $HELPERS_CFG not defined use $HOME/opt
if test -z "$HELPERS_OPT_WIN"; then
  HELPERS_OPT_WIN="/c/opt"
fi
if test -z "$HELPERS_OPT_LINUX"; then
  HELPERS_OPT_LINUX="/opt"
fi

# if $HELPERS_DEV not defined use $HOME/dev
if test -z "$HELPERS_DEV"; then
  HELPERS_DEV="$HOME/dev"
fi

# ---------------------------------------
# load extra helpers vars from .helpers-cfg.sh
# ---------------------------------------

# if not "$HOME/.helpers-cfg.sh" load skel
if test -f "$HOME/.helpers-cfg.sh"; then
  HELPERS_CFG="$HOME/.helpers-cfg.sh"
else
  HELPERS_CFG="$SCRIPT_DIR/skel/.helpers-cfg.sh"
fi
if test -f $HELPERS_CFG; then
  source $HELPERS_CFG
fi

# ---------------------------------------
# log funcs
# ---------------------------------------

alias hf_log_func='hf_log_msg "${FUNCNAME[0]}"'
alias hf_log_not_implemented_return="hf_log_error 'Not implemented'; return;"

function hf_log_wrap() {
  echo -e "$1" | fold -w100 -s
}

function hf_log_error() {
  hf_log_wrap "\033[00;31m-- $* \033[00m"
}

function hf_log_msg() {
  hf_log_wrap "\033[00;33m-- $* \033[00m"
}

function hf_log_msg_2nd() {
  hf_log_wrap "\033[00;33m-- > $* \033[00m"
}

function hf_log_done() {
  hf_log_wrap "\033[00;32m-- done\033[00m"
}

function hf_log_ok() {
  hf_log_wrap "\033[00;32m-- ok\033[00m"
}

function hf_log_try() {
  "$@"
  if $? -ne 0; then hf_log_error "$1" && exit 1; fi
}

# ---------------------------------------
# test funcs
# ---------------------------------------

alias hf_test_noargs_then_return='if $# -eq 0; then return; fi'
alias hf_test_arg1_then_return='if test -z "$1"; then return; fi'

function hf_test_and_create_folder() {
  if test ! -d $1; then
    hf_log_msg "creating $1"
    mkdir -p $1
  fi
}

function hf_test_and_create_file() {
  : ${1?"Usage: ${FUNCNAME[0]} [file]"}
  if ! test -f "$1"; then
    hf_test_and_create_folder $(dirname $1)
    touch "$1"
  fi
}

function hf_test_and_delete_remove() {
  if test -d $1; then rm -rf $1; fi
}

# ---------------------------------------
# load libs for specific commands
# ---------------------------------------

if type adb &>/dev/null; then source "$SCRIPT_DIR/lib/android.sh"; fi
if type apt &>/dev/null; then source "$SCRIPT_DIR/lib/deb.sh"; fi
if type arp-scan &>/dev/null; then source "$SCRIPT_DIR/lib/arp-scan.sh"; fi
if type cmake &>/dev/null; then source "$SCRIPT_DIR/lib/cmake.sh"; fi
if type code &>/dev/null; then source "$SCRIPT_DIR/lib/code.sh"; fi
if type curl &>/dev/null; then source "$SCRIPT_DIR/lib/curl.sh"; fi
if type diff &>/dev/null; then source "$SCRIPT_DIR/lib/diff.sh"; fi
if type docker &>/dev/null; then source "$SCRIPT_DIR/lib/docker.sh"; fi
if type du &>/dev/null; then source "$SCRIPT_DIR/lib/folder-size.sh"; fi
if type ffmpeg &>/dev/null; then source "$SCRIPT_DIR/lib/ffmpeg.sh"; fi
if type find &>/dev/null; then source "$SCRIPT_DIR/lib/find.sh"; fi
if type flutter &>/dev/null; then source "$SCRIPT_DIR/lib/flutter.sh"; fi
if type gcc &>/dev/null; then source "$SCRIPT_DIR/lib/gcc.sh"; fi
if type git &>/dev/null; then source "$SCRIPT_DIR/lib/git.sh"; fi
if type gnome-shell &>/dev/null; then source "$SCRIPT_DIR/lib/gnome.sh"; fi
if type gst &>/dev/null; then source "$SCRIPT_DIR/lib/gst.sh"; fi
if type gst-launch-1.0 &>/dev/null; then source "$SCRIPT_DIR/lib/gst.sh"; fi
if type jupyter &>/dev/null; then source "$SCRIPT_DIR/lib/jupyter.sh"; fi
if type lsof &>/dev/null; then source "$SCRIPT_DIR/lib/ports.sh"; fi
if type lxc &>/dev/null; then source "$SCRIPT_DIR/lib/lxc.sh"; fi
if type mount &>/dev/null; then source "$SCRIPT_DIR/lib/mount.sh"; fi
if type pandoc &>/dev/null; then source "$SCRIPT_DIR/lib/pandoc.sh"; fi
if type pdflatex &>/dev/null; then source "$SCRIPT_DIR/lib/pdflatex.sh"; fi
if type pdftk ghostscript &>/dev/null; then source "$SCRIPT_DIR/lib/pdf.sh"; fi
if type pkg-config &>/dev/null; then source "$SCRIPT_DIR/lib/pkg-config.sh"; fi
if type pngquant jpegoptim &>/dev/null; then source "$SCRIPT_DIR/lib/image.sh"; fi
if type pygmentize &>/dev/null; then source "$SCRIPT_DIR/lib/pygmentize.sh"; fi
if type pygmentize &>/dev/null; then source "$SCRIPT_DIR/lib/pygmentize.sh"; fi
if type python &>/dev/null; then source "$SCRIPT_DIR/lib/python.sh"; fi
if type ruby &>/dev/null; then source "$SCRIPT_DIR/lib/ruby.sh"; fi
if type snap &>/dev/null; then source "$SCRIPT_DIR/lib/snap.sh"; fi
if type ssh &>/dev/null; then source "$SCRIPT_DIR/lib/ssh.sh"; fi
if type tesseract &>/dev/null; then source "$SCRIPT_DIR/lib/tesseract.sh"; fi
if type tlshell.exe &>/dev/null; then source "$SCRIPT_DIR/lib/texlive-win.sh"; fi
if type wget &>/dev/null; then source "$SCRIPT_DIR/lib/wget.sh"; fi
if type youtube-dl &>/dev/null; then source "$SCRIPT_DIR/lib/youtube-dl.sh"; fi
if type zip tar &>/dev/null; then source "$SCRIPT_DIR/lib/compression.sh"; fi

source "$SCRIPT_DIR/lib/rename.sh"
source "$SCRIPT_DIR/lib/md5.sh"

# ---------------------------------------
# load libs for specific OS
# ---------------------------------------

if $IS_LINUX; then
  if $IS_WINDOWS_UBUNTU; then
    source "$SCRIPT_DIR/lib/linux-ubuntu.sh"
  fi
  source "$SCRIPT_DIR/lib/linux.sh"
elif $IS_WINDOWS; then
  if $IS_WINDOWS_MSYS; then
    source "$SCRIPT_DIR/lib/win-msys.sh"
  elif $IS_WINDOWS_WSL; then
    source "$SCRIPT_DIR/lib/win-wsl.sh"
  fi
  source "$SCRIPT_DIR/lib/win.sh"
elif $IS_MAC; then
  source "$SCRIPT_DIR/lib/mac.sh"
fi

# ---------------------------------------
# update_clean
# ---------------------------------------

function hf_update_clean() {
  if $IS_LINUX_UBUNTU; then
    hf_update_clean_ubuntu
  elif $IS_WINDOWS; then
    hf_update_clean_windows
  elif $IS_MAC; then
    hf_update_clean_mac
  fi
}

# ---------------------------------------
# config
# ---------------------------------------

function hf_config_func() {
  : ${1?"Usage: ${FUNCNAME[0]} backup|install|diff"}
  hf_log_func
  declare -a files_array
  if $IS_LINUX; then
    files_array=($BKP_FILES $BKP_FILES_LINUX)
  elif $IS_WINDOWS; then
    files_array=($BKP_FILES $BKP_FILES_WIN)
  elif $IS_MAC; then
    files_array=($BKP_FILES $BKP_FILES_MAC)
  fi
  for ((i = 0; i < ${#files_array[@]}; i = i + 2)); do
    hf_test_and_create_file ${files_array[$i]}
    hf_test_and_create_file ${files_array[$((i + 1))]}
    if $1 = "backup"; then
      cp ${files_array[$i]} ${files_array[$((i + 1))]}
    elif $1 = "install"; then
      cp ${files_array[$((i + 1))]} ${files_array[$i]}
    elif $1 = "diff"; then
      ret=$(diff ${files_array[$i]} ${files_array[$((i + 1))]})
      if $? = 1; then
        hf_log_msg "diff ${files_array[$i]} ${files_array[$((i + 1))]}"
        echo "$ret"
      fi
    fi
  done
}
alias hf_config_install="hf_config_func install"
alias hf_config_backup="hf_config_func backup"
alias hf_config_diff="hf_config_func diff"

# ---------------------------------------
# profile funcs
# ---------------------------------------

function hf_profile_install() {
  hf_log_func
  echo -e "\nsource $SCRIPT_NAME" >>$HOME/.bashrc
}

function hf_profile_reload() {
  hf_log_func
  if $IS_WINDOWS_WSL; then
    # for WSL
    source $HOME/.profile
  else
    source $HOME/.bashrc
  fi
}

# ---------------------------------------
# home
# ---------------------------------------

HF_CLEAN_DIRS=(
  'Images'
  'Movies'
  'Public'
  'Templates'
  'Tracing'
  'Videos'
  'Music'
  'Pictures'
)

if $IS_LINUX; then
  HF_CLEAN_DIRS+=(
    'Documents' # sensible data in Windows
  )
fi

if $IS_WINDOWS; then
  HF_CLEAN_DIRS+=(
    'Application Data'
    'Cookies'
    'OpenVPN'
    'Local Settings'
    'Start Menu'
    '3D Objects'
    'Contacts'
    'Favorites'
    'Intel'
    'IntelGraphicsProfiles'
    'Links'
    'MicrosoftEdgeBackups'
    'My Documents'
    'NetHood'
    'PrintHood'
    'Recent'
    'Saved Games'
    'Searches'
    'SendTo'
  )
fi

function hf_home_clean_unused_dirs() {
  hf_log_func
  for i in "${HF_CLEAN_DIRS[@]}"; do
    if test -d "$HOME/$i"; then
      if $IS_MAC; then
        sudo rm -rf "$HOME/${i:?}" >/dev/null
      else
        rm -rf "$HOME/${i:?}" >/dev/null
      fi
    elif test -f "$HOME/$i"; then
      echo remove $i
      if $IS_MAC; then
        sudo rm -f "$HOME/$i" >/dev/null
      else
        rm -f "$HOME/${i:?}" >/dev/null
      fi
    fi
  done
}
