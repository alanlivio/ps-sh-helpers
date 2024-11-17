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
    *.bz2) ret=$(tar -xjf "$1" -C $dest) ;;
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
