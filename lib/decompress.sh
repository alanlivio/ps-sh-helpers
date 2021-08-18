# ---------------------------------------
# decompress helpers
# ---------------------------------------

function bh_decompress_zip() {
  : ${1?"Usage: ${FUNCNAME[0]} <zip-name>"}
  unzip $1 -d "${1%%.zip}"
}

function bh_decompress_zip_list() {
  : ${1?"Usage: ${FUNCNAME[0]} <zip-name>"}
  unzip -l $1
}

function bh_decompress() {
  : ${1?"Usage: ${FUNCNAME[0]} <zip-name> [folder-name]"}
  local EXT=${1##*.}
  local DST
  if [ $# -eq 1 ]; then
    DST=.
  else
    DST=$2
  fi

  case $EXT in
  tgz)
    tar -xzf $1 -C $DST
    ;;
  gz) # consider tar.gz
    tar -xf $1 -C $DST
    ;;
  bz2) # consider tar.bz2
    tar -xjf $1 -C $DST
    ;;
  zip)
    unzip $1 -d $DST
    ;;
  xz)
    tar -xJf $1 -C $DST
    ;;
  *)
    bh_log_error "$EXT is not supported compress." && exit
    ;;
  esac
}

function bh_decompress_from_url() {
  : ${2?"Usage: ${FUNCNAME[0]} <URL> <folder>"}
  local file_name="/tmp/$(basename $1)"

  if test ! -f $file_name; then
    bh_curl_fetch_to_dir $1 /tmp/
  fi
  echo "extracting $file_name to $2"
  bh_decompress $file_name $2
}
