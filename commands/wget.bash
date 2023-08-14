function wget_get_headers() {
    wget --server-response -O- $1
}

function wget_post_json() {
    wget --server-response -O- $1 --post-data="$2" --header='Content-Type:application/json'
}

function wget_post_file() {
    wget --server-response -O- $1 --post-file="$2" --header='Content-Type:application/json'
}

function wget_continue() {
    wget --continue $1
}
