#!/bin/bash

BH_DIR="$(dirname "${BASH_SOURCE[0]}")"

# load os_any.bash

source "$BH_DIR/os_any.bash"

# load any os_<name>.bash files

if [[ $OSTYPE == msys* || -n $WSL_DISTRO_NAME ]]; then
    source "$BH_DIR/os_win.bash"
fi

if [[ $OSTYPE == linux* ]]; then
    source "$BH_DIR/os_ubu.bash"
fi

if [[ $OSTYPE == darwin* ]]; then
    source "$BH_DIR/os_mac.bash"
fi

# load <program>.bash files

for file in "$BH_DIR/programs/"*.bash; do
    program=$(basename ${file%.*})
    if type $program &>/dev/null; then
        source $file
    fi
done
