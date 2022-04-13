# ---------------------------------------
# wget
# ---------------------------------------

function bh_wget_get_headers() {
  wget --server-response -O- $1
}

function bh_wget_post_json() {
  wget --server-response -O- $1 --post-data="$2" --header='Content-Type:application/json'
}

function bh_wget_post_file() {
  wget --server-response -O- $1 --post-file="$2" --header='Content-Type:application/json'
}

function bh_wget_continue() {
  wget --continue $1
}
