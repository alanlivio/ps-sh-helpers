# -- any OS --

HELPERS_DIR="$(dirname "${BASH_SOURCE[0]}")"
function log_error() { echo -e "\033[00;31m-- $* \033[00m"; }
function log_msg() { echo -e "\033[00;33m-- $* \033[00m"; }
alias bashrc_reload='source $HOME/.bashrc'
alias folder_count_files='find . -maxdepth 1 -type f | wc -l'
alias folder_count_files_recusive='find . -maxdepth 1 -type f | wc -l'
alias folder_list_sorted_by_size='du -ahd 1 | sort -h'
alias folder_find_file_with_crlf='find . -not -type d -exec file "{}" ";" | grep CRLF'
alias passwd_generate='echo $(tr -dc "A-Za-z0-9!?%=" < /dev/urandom | head -c 12)'

# -- _ helpers to create aliases --

function _ps_call() {
    powershell -command "& { . $(wslpath -w $HELPERS_DIR/init.ps1); $* }"
}

function _ps_def_func() {
    if ! typeset -f $1 >/dev/null 2>&1; then
        eval 'function '$1'() { _ps_call' $1 '$*; }'
    fi
}

function _ps_aliases_to_funcs_at_ps1_file() {
    : ${1?"Usage: ${FUNCNAME[0]} <ps1_file>"}
    # load functions from file that does not start with _
    # TODO: skip if exists
    if test -f $1; then
        _regex_no_underscore_func='function\s([^_][^{]+)\('
        while read -r line; do
            if [[ $line =~ $_regex_no_underscore_func ]]; then
                func=${BASH_REMATCH[1]}
                _ps_def_func $func
            fi
        done <$1
    else
        echo "$1 does not exist"
    fi
}

# -- load os/<name>.bash files --

if [[ $OSTYPE == msys* || -n $WSL_DISTRO_NAME ]]; then
    source "$HELPERS_DIR/os/win.bash"
    _ps_aliases_to_funcs_at_ps1_file "$HELPERS_DIR/os/win.ps1"
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
