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

# ---------------------------------------
# fetch
# ---------------------------------------

function bh_wget_extract () {
  : ${2?"Usage: ${FUNCNAME[0]} <URL> <folder>"}
  local file_name="/tmp/$(basename $1)"

  if test ! -f $file_name; then
    echo "fetching $file_name"
    cd /tmp/
    wget --continue $1
    if test $? != 0; then bh_log_error "wget failed." && return 1; fi
    cd -
  fi
  echo "extracting $file_name to $2"
  bh_compression_extract $file_name $2
}
