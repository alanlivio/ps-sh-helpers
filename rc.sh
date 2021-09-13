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
HAS_GNOME=false
HAS_SNAP=false
HAS_VSCODE=false
HAS_PYTHON=false

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
BH_SKEL_VSCODE="$BH_DIR/skel/vscode"

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
# essentials
# ---------------------------------------

source "$BH_DIR/lib/log-test.sh"   # uses echo, test, md5
source "$BH_DIR/lib/curl.sh"       # uses curl
source "$BH_DIR/lib/home.sh"       # uses cp
source "$BH_DIR/lib/decompress.sh" # uses tar, unzip, curl
source "$BH_DIR/lib/rename.sh"     # uses rename
source "$BH_DIR/lib/folder.sh"     # uses du, find

function bh_bashrc_reload() {
  bh_log_func
  if $IS_WINDOWS_WSL; then
    source $HOME/.profile
  else
    source $HOME/.bashrc
  fi
}

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
# load helpers for specific commands
# ---------------------------------------
if type code &>/dev/null; then
  HAS_VSCODE=true
  source "$BH_DIR/lib/vscode.sh"
fi
if type pip &>/dev/null; then
  HAS_PYTHON=true
  source "$BH_DIR/lib/python.sh"
fi

if type adb &>/dev/null; then source "$BH_DIR/lib/android.sh"; fi
if type arp-scan &>/dev/null; then source "$BH_DIR/lib/arp-scan.sh"; fi
if type cmake &>/dev/null; then source "$BH_DIR/lib/cmake.sh"; fi
if type diff &>/dev/null; then source "$BH_DIR/lib/diff.sh"; fi
if type docker &>/dev/null; then source "$BH_DIR/lib/docker.sh"; fi
if type ffmpeg &>/dev/null; then source "$BH_DIR/lib/ffmpeg.sh"; fi
if type flutter &>/dev/null; then source "$BH_DIR/lib/flutter.sh"; fi
if type gcc &>/dev/null; then source "$BH_DIR/lib/gcc.sh"; fi
if type git &>/dev/null; then source "$BH_DIR/lib/git.sh"; fi
if type gst &>/dev/null; then source "$BH_DIR/lib/gst.sh"; fi
if type gst-launch-1.0 &>/dev/null; then source "$BH_DIR/lib/gst.sh"; fi
if type jupyter &>/dev/null; then source "$BH_DIR/lib/jupyter.sh"; fi
if type mount &>/dev/null; then source "$BH_DIR/lib/mount.sh"; fi
if type pandoc &>/dev/null; then source "$BH_DIR/lib/pandoc.sh"; fi
if type pdflatex &>/dev/null; then source "$BH_DIR/lib/pdflatex.sh"; fi
if type pdftk ghostscript &>/dev/null; then source "$BH_DIR/lib/pdf.sh"; fi
if type pkg-config &>/dev/null; then source "$BH_DIR/lib/pkg-config.sh"; fi
if type pngquant jpegoptim &>/dev/null; then source "$BH_DIR/lib/image.sh"; fi
if type pygmentize &>/dev/null; then source "$BH_DIR/lib/pygmentize.sh"; fi
if type ruby &>/dev/null; then source "$BH_DIR/lib/ruby.sh"; fi
if type ssh &>/dev/null; then source "$BH_DIR/lib/ssh.sh"; fi
if type tesseract &>/dev/null; then source "$BH_DIR/lib/tesseract.sh"; fi
if type wget &>/dev/null; then source "$BH_DIR/lib/wget.sh"; fi
if type youtube-dl &>/dev/null; then source "$BH_DIR/lib/youtube-dl.sh"; fi
if type zip tar &>/dev/null; then source "$BH_DIR/lib/zip.sh"; fi
if test -d /etc/sudoers.d/; then source "$BH_DIR/lib/user.sh"; fi

# ---------------------------------------
# load libs for specific OS
# ---------------------------------------

if $IS_LINUX_UBUNTU; then
  source "$BH_DIR/rc-ubuntu.sh"
elif $IS_WINDOWS_MSYS; then
  source "$BH_DIR/rc-msys.sh"
elif $IS_WINDOWS_WSL; then
  source "$BH_DIR/rc-ubuntu.sh"
  source "$BH_DIR/rc-wsl.sh"
elif $IS_WINDOWS_GITBASH; then
  source "$BH_DIR/rc-gitbash.sh"
elif $IS_MAC; then
  source "$BH_DIR/rc-mac.sh"
fi
