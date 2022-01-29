#!/bin/bash

# ---------------------------------------
# OS vars
# ---------------------------------------

IS_MAC=false
IS_LINUX=false
IS_LINUX_UBU=false
IS_WIN=false
IS_WIN_WSL=false
IS_WIN_MSYS=false
IS_WIN_GITBASH=false

case "$(uname -s)" in
CYGWIN* | MINGW* | MSYS*)
  IS_WIN=true
  if test -e /etc/profile.d/git-prompt.sh; then
    IS_WIN_GITBASH=true
  else
    IS_WIN_MSYS=true
  fi
  ;;
Linux)
  if [[ $(uname -r) == *"icrosoft"* ]]; then
    IS_WIN=true
    IS_WIN_WSL=true
  elif [[ $(lsb_release -d | awk '{print $2}') == Ubuntu ]]; then
    IS_LINUX=true
    IS_LINUX_UBU=true
  fi
  ;;
Darwin)
  IS_MAC=true
  ;;
esac

# ---------------------------------------
# load helpers
# ---------------------------------------
BH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BH_RC="$BH_DIR/rc.sh"
# if not "$HOME/.bh-cfg.sh" copy skel
if ! test -f "$HOME/.bh-cfg.sh"; then cp $BH_DIR/skel/.bh-cfg.sh $HOME/; fi
# load from from .bh-cfg.sh
source $HOME/.bh-cfg.sh
source "$BH_DIR/lib/base.sh" # uses echo, test, md5, curl, tar, unzip, curl, rename, find

if $IS_LINUX_UBU; then
  source "$BH_DIR/lib/rc-ubu.sh"
elif $IS_WIN_MSYS; then
  source "$BH_DIR/lib/rc-msys.sh"
elif $IS_WIN_WSL; then
  source "$BH_DIR/lib/rc-ubu.sh"
  source "$BH_DIR/lib/rc-wsl.sh"
elif $IS_WIN_GITBASH; then
  source "$BH_DIR/lib/rc-win.sh"
elif $IS_MAC; then
  source "$BH_DIR/lib/rc-mac.sh"
fi