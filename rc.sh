#!/bin/bash

# ---------------------------------------
# OS vars
# ---------------------------------------

declare IS_{MAC,UBU,LINUX,WIN,WSL,MSYS,GITBASH}=false

case "$(uname -s)" in
CYGWIN* | MINGW* | MSYS*)
  IS_WIN=true
  if test -e /etc/profile.d/git-prompt.sh; then
    IS_GITBASH=true
  else
    IS_MSYS=true
  fi;;
Linux)
  if [[ $(uname -r) == *"icrosoft"* ]]; then
    IS_WIN=true
    IS_WSL=true
  elif [[ $(lsb_release -d | awk '{print $2}') == Ubuntu ]]; then
    IS_UBU=true
  fi
  IS_LINUX=true;;
Darwin) IS_MAC=true;;
esac

# ---------------------------------------
# load .bh-cfg.sh and helpers
# ---------------------------------------
BH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BH_RC="$BH_DIR/rc.sh"

# if not "$HOME/.bh-cfg.sh". load from skel
if test -f "$HOME/.bh-cfg.sh"; then 
  source $HOME/.bh-cfg.sh
else
  source $BH_DIR/skel/.bh-cfg.sh 
fi

source "$BH_DIR/lib/base.sh" # uses echo, test, md5, curl, tar, unzip, curl, rename, find

if $IS_UBU; then
  source "$BH_DIR/lib/rc-ubu.sh"
elif $IS_MSYS; then
  source "$BH_DIR/lib/rc-msys.sh"
elif $IS_WSL; then
  source "$BH_DIR/lib/rc-ubu.sh"
  source "$BH_DIR/lib/rc-wsl.sh"
elif $IS_GITBASH; then
  source "$BH_DIR/lib/rc-gitbash.sh"
elif $IS_MAC; then
  source "$BH_DIR/lib/rc-mac.sh"
fi