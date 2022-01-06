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
  if test -f /etc/profile.d/git-prompt.sh; then
    IS_WINDOWS_GITBASH=true
  else
    IS_WINDOWS_MSYS=true
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
# bh vars
# ---------------------------------------

BH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BH_RC="$BH_DIR/rc.sh"

# ---------------------------------------
# bh vars from .bh-cfg.sh vars
# ---------------------------------------

# if not "$HOME/.bh-cfg.sh" copy skel
if ! test -f "$HOME/.bh-cfg.sh"; then cp $BH_DIR/skel/.bh-cfg.sh $HOME/; fi
source $HOME/.bh-cfg.sh
# set some var if .bh-cfg do not.
if test -z "$BH_OPT_WIN"; then BH_OPT_WIN="$HOME/AppData/Local/Programs"; fi
if test -z "$BH_OPT_LINUX"; then BH_OPT_LINUX="$HOME/opt"; fi
if test -z "$BH_DEV"; then BH_DEV="$HOME/dev"; fi

# ---------------------------------------
# essentials helpers
# ---------------------------------------

source "$BH_DIR/lib/essentials.sh" # uses echo, test, md5, curl, tar, unzip, curl, rename, find

# ---------------------------------------
# bh helpers
# ---------------------------------------

function bh_bh_update_from_github_and_reload() {
  bh_log_func
  cd $BH_DIR && git pull && cd $OLDPWD
  bh_bashrc_reload
}

function bh_bh_install() {
  bh_log_func
  local line='source $HOME/.bh/rc.sh'
  if ! grep -Fxq "$line" $HOME/.bashrc; then
    echo -e "$line\n" >>$HOME/.bashrc
  fi
}

# ---------------------------------------
# specific-OS helpers
# ---------------------------------------

if $IS_LINUX_UBUNTU; then
  source "$BH_DIR/lib/rc-ubu.sh"
elif $IS_WINDOWS_MSYS; then
  source "$BH_DIR/lib/rc-msys.sh"
elif $IS_WINDOWS_WSL; then
  source "$BH_DIR/lib/rc-ubu.sh"
  source "$BH_DIR/lib/rc-wsl.sh"
elif $IS_WINDOWS_GITBASH; then
  source "$BH_DIR/lib/rc-win.sh"
elif $IS_MAC; then
  source "$BH_DIR/lib/rc-mac.sh"
fi

# ---------------------------------------
# specifc-commands helpers
# ---------------------------------------

if type code &>/dev/null; then
  HAS_VSCODE=true
  source "$BH_DIR/lib/cross/vscode.sh"
fi
if type pip &>/dev/null; then
  HAS_PYTHON=true
  source "$BH_DIR/lib/cross/python.sh"
fi

if type adb &>/dev/null; then source "$BH_DIR/lib/cross/adb.sh"; fi
if type cmake &>/dev/null; then source "$BH_DIR/lib/cross/cmake.sh"; fi
if type docker &>/dev/null; then source "$BH_DIR/lib/cross/docker.sh"; fi
if type ffmpeg &>/dev/null; then source "$BH_DIR/lib/cross/ffmpeg.sh"; fi
if type flutter &>/dev/null; then source "$BH_DIR/lib/cross/flutter.sh"; fi
if type gcc &>/dev/null; then source "$BH_DIR/lib/cross/gcc.sh"; fi
if type git &>/dev/null; then source "$BH_DIR/lib/cross/git.sh"; fi
if type gst-launch-1.0 &>/dev/null; then source "$BH_DIR/lib/cross/gst.sh"; fi
if type pandoc &>/dev/null; then source "$BH_DIR/lib/cross/pandoc.sh"; fi
if type ghostscript &>/dev/null; then source "$BH_DIR/lib/cross/ghostscript.sh"; fi
if type pdflatex &>/dev/null; then source "$BH_DIR/lib/cross/pdflatex.sh"; fi
if type pkg-config &>/dev/null; then source "$BH_DIR/lib/cross/pkg-config.sh"; fi
if type ruby &>/dev/null; then source "$BH_DIR/lib/cross/ruby.sh"; fi
if type ssh &>/dev/null; then source "$BH_DIR/lib/cross/ssh.sh"; fi
if type tesseract &>/dev/null; then source "$BH_DIR/lib/cross/tesseract.sh"; fi
if type wget &>/dev/null; then source "$BH_DIR/lib/cross/wget.sh"; fi
if type youtube-dl &>/dev/null; then source "$BH_DIR/lib/cross/youtube-dl.sh"; fi
if type zip tar &>/dev/null; then source "$BH_DIR/lib/cross/zip.sh"; fi