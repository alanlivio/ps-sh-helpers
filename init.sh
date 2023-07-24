#!/bin/bash

BH_DIR="$(dirname "${BASH_SOURCE[0]}")"

#########################
# load os_<name>.bash files
#########################

source "$BH_DIR/os_any.bash"

if [[ $OSTYPE == msys* || -n $WSL_DISTRO_NAME ]]; then
  source "$BH_DIR/os_win.bash"
fi

if [[ $OSTYPE == linux* ]]; then
  source "$BH_DIR/os_ubu.bash"
fi

if [[ $OSTYPE == darwin* ]]; then
  "$BH_DIR/os_mac.bash"
fi

#########################
# load <command>.bash files
#########################

for file in "$BH_DIR/commands/"*.bash; do
  command_name=$(basename ${file%.*})
  if type $command_name &>/dev/null; then
    source $file
  fi
done