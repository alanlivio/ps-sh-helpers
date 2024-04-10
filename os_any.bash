# -- essentials --

alias bashrc_reload='source $HOME/.bashrc'
alias folder_count_files='find . -maxdepth 1 -type f | wc -l'
alias folder_count_files_recusive='find . -maxdepth 1 -type f | wc -l'
alias folder_list_sorted_by_size='du -ahd 1 | sort -h'
alias folder_find_file_with_crlf='find . -not -type d -exec file "{}" ";" | grep CRLF'

function log_error() { echo -e "\033[00;31m-- $* \033[00m"; }
function log_msg() { echo -e "\033[00;33m-- $* \033[00m"; }
function log_msg2() { echo -e "\033[00;33m-- > $* \033[00m"; }

function _dotfiles_func() {
    : ${1?"Usage: ${FUNCNAME[0]} <backup|install|diff>"}
    declare -a files_array
    files_array=($BH_DOTFILES)
    if [ ${#files_array[@]} -eq 0 ]; then log_error "BH_DOTFILES empty" && return 1; fi
    for ((i = 0; i < ${#files_array[@]}; i = i + 2)); do
        if [ "$1" = "backup" ]; then
            cp ${files_array[$i]} ${files_array[$((i + 1))]}
        elif [ "$1" = "install" ]; then
            cp ${files_array[$((i + 1))]} ${files_array[$i]}
        elif [ "$1" = "diff" ]; then
            ret=$(diff ${files_array[$i]} ${files_array[$((i + 1))]})
            if [ $? = 1 ]; then
                log_msg "diff ${files_array[$i]} ${files_array[$((i + 1))]}"
                echo "$ret"
            fi
        fi
    done
}
alias bh_dotfiles_install="_dotfiles_func install"
alias bh_dotfiles_backup="_dotfiles_func backup"
alias bh_dotfiles_diff="_dotfiles_func diff"

alias password_generate='echo $(tr -dc "A-Za-z0-9!?%=" < /dev/urandom | head -c 10)'

# -- clean --

function latex_clean() {
    rm -rf comment.cut ./*.aux ./*.dbx ./*.bbx ./*.cbx ./*.dvi ./*.log ./*.lox ./*.out ./*.lol ./*.pdf ./*.synctex.gz ./_minted-* ./*.bbl ./*.blg ./*.lot ./*.lof ./*.toc ./*.lol ./*.fdb_latexmk ./*.fls ./*.bcf ./*.aux ./*.fls ./*.fdb_latexmk ./*.log
}

# -- arp --

function arp_list() {
    if [[ $OSTYPE == "msys"* ]]; then
        arp //a
    else
        arp -a
    fi
}

# -- decompress --

function decompress() {
    : ${1?"Usage: ${FUNCNAME[0]} <zip-name> [dir-name]"}
    local filename=$(basename $1)
    local filename_noext="${filename%.*}"
    local extension=${path##*.}
    local dest
    if [ $# -eq 1 ]; then dest=.; else dest=$2; fi
    case $filename in
    *.tar.bz2 | *.tbz | *.tbz2) ret=$(tar -xzf "$1" -C $dest) ;;
    *.gz | *.Z) ret=$(gunzip "$1" >$dest/$filename_noext) ;;
    *bz2) ret=$(tar -xjf "$1" -C $dest) ;;
    *.zip) ret=$(unzip "$1" -d $dest) ;;
    *.zst) ret=$(tar --use-compress-program=unzstd -xvf "$1" -C $dest) ;;
    *.xz) ret=$(tar -xJf "$1" -C $dest) ;;
    *) log_error "$extension is not supported compress." && return 1 ;;
    esac
    if [ $? != 0 ] || ! [ -f $file_name ]; then
        log_error "decompress "$1" failed " && return 1
    fi
}

function decompress_from_url() {
    : ${2?"Usage: ${FUNCNAME[0]} <URL> <dir>"}
    local file_name="/tmp/$(basename $1)"
    if test ! -e $file_name; then
        log_msg "fetching "$1" to /tmp/"
        curl -LJ "$1" --create-dirs --output $file_name
        if [ $? != 0 ]; then log_error "curl fail" && return; fi
    fi
    log_msg "extracting $file_name to $2"
    decompress $file_name $2
}

# -- ssh --

function ssh_send_to_server_authorized_pub_key() {
    : ${1?"Usage: ${FUNCNAME[0]} <user@server>"}
    ssh "$1" sh -c 'cat - >> ~/.ssh/authorized_keys' <$HOME/.ssh/id_rsa.pub
}

function ssh_send_to_server_priv_key() {
    : ${1?"Usage: ${FUNCNAME[0]} <user@server>"}
    ssh "$1" sh -c 'cat - > ~/.ssh/id_rsa;chmod 600 $HOME/.ssh/id_rsa' <$HOME/.ssh/id_rsa
}
