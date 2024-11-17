HELPERS_DIR="$(dirname "${BASH_SOURCE[0]}")"

# -- bash basic --
function log_error() { echo -e "\033[00;31m-- $* \033[00m"; }
function log_msg() { echo -e "\033[00;33m-- $* \033[00m"; }
alias bashrc_reload='source $HOME/.bashrc'
alias folder_count_files='find . -maxdepth 1 -type f | wc -l'
alias folder_count_files_recusive='find . -maxdepth 1 -type f | wc -l'
alias folder_list_sorted_by_size='du -ahd 1 | sort -h'
alias folder_find_file_with_crlf='find . -not -type d -exec file "{}" ";" | grep CRLF'
alias passwd_generate='echo $(tr -dc "A-Za-z0-9!?%=" < /dev/urandom | head -c 12)'
function ssh_fix_permisisons() {
    # https://stackoverflow.com/questions/9270734/ssh-permissions-are-too-open
    chmod 700 $HOME/.ssh/
    chmod 600 $HOME/.ssh/id_rsa
    chmod 600 $HOME/.ssh/id_rsa.pubssh-rsa
}

# -- load os_<name>.bash files --

if [[ $OSTYPE == msys* || -n $WSL_DISTRO_NAME ]]; then
    source "$HELPERS_DIR/os_win.bash"
fi
if [[ $OSTYPE == linux* ]]; then
    source "$HELPERS_DIR/os_ubu.bash"
fi

# -- load <program>.bash files --

for file in "$HELPERS_DIR/programs/"*.bash; do
    program=$(basename ${file%.*})
    if type $program &>/dev/null; then
        source $file
    fi
done
