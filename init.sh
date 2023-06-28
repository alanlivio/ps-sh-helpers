#!/bin/bash

BH_DIR="$(dirname "${BASH_SOURCE[0]}")"

#########################
# load os_<name>.bash files
#########################

source "$BH_DIR/os_any.bash"
case $OSTYPE in
msys*)
  source "$BH_DIR/os_win.bash"
  alias winpath='cygpath -m'
  ;;
linux*)
  source "$BH_DIR/os_ubu.bash"
  if [[ -n $WSL_DISTRO_NAME ]]; then
    alias winpath='wslpath -m'
    source "$BH_DIR/os_win.bash";
  fi
  ;;
darwin*)
  source "$BH_DIR/os_mac.bash"
  ;;
esac

#########################
# load <command>.bash files
#########################

for file in "$BH_DIR/lib/"*.bash; do
  command_name=$(basename ${file%.*})
  if type $command_name &>/dev/null; then
    source $file
  fi
done