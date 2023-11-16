function wget_get_headers() {
    : ${1?"Usage: ${FUNCNAME[0]} <url>"}
    wget --server-response -O- $1
}

function wget_post_json() {
    : ${1?"Usage: ${FUNCNAME[0]} <url>"}
    wget --server-response -O- "$1" --post-data="$2" --header='Content-Type:application/json'
}

function wget_post_file() {
    : ${1?"Usage: ${FUNCNAME[0]} <url>"}
    wget --server-response -O- "$1" --post-file="$2" --header='Content-Type:application/json'
}

function wget_continue() {
    : ${1?"Usage: ${FUNCNAME[0]} <url>"}
    wget --continue $1
}
