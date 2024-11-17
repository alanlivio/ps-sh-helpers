HELPERS_DIR="$(dirname "${BASH_SOURCE[0]}")"

# load os_any.bash

source "$HELPERS_DIR/os_any.bash"

# load os_<name>.bash files

if [[ $OSTYPE == msys* || -n $WSL_DISTRO_NAME ]]; then
    source "$HELPERS_DIR/os_win.bash"
fi
if [[ $OSTYPE == linux* ]]; then
    source "$HELPERS_DIR/os_ubu.bash"
fi

# load <program>.bash files

for file in "$HELPERS_DIR/programs/"*.bash; do
    program=$(basename ${file%.*})
    if type $program &>/dev/null; then
        source $file
    fi
done
