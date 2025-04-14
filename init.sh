HELPERS_DIR="$(dirname "${BASH_SOURCE[0]}")"

# -- load os/<name>.bash files --

source "$HELPERS_DIR/os/any.bash"

if [[ $OSTYPE == msys* || -n $WSL_DISTRO_NAME ]]; then
    source "$HELPERS_DIR/os/win.bash"
    ps_def_funcs_from_ps1_file "$HELPERS_DIR/os/win.ps1"
fi
if [[ $OSTYPE == linux* ]]; then
    source "$HELPERS_DIR/os/ubu.bash"
fi

# -- load <program>.bash files --

for file in "$HELPERS_DIR/programs/"*.bash; do
    program=$(basename ${file%.*})
    if type $program &>/dev/null; then
        source $file
    fi
done
