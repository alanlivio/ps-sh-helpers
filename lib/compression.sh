function hf_compression_zip_files() {
  : ${2?"Usage: ${FUNCNAME[0]} <zip-name> <files... >"}
  zipname=$1
  shift
  zip "$zipname" -r "$@"
}

function hf_compression_zip_folder() {
  : ${1?"Usage: ${FUNCNAME[0]} <folder-name>"}
  zip "$(basename $1).zip" -r $1
}

function hf_compression_zip_extract() {
  : ${1?"Usage: ${FUNCNAME[0]} <zip-name>"}
  unzip $1 -d "${1%%.zip}"
}

function hf_compression_zip_list() {
  : ${1?"Usage: ${FUNCNAME[0]} <zip-name>"}
  unzip -l $1
}

function hf_compression_extract() {
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
  rar)
    unrar x $1 -C $DST
    ;;
  *)
    hf_log_error "$EXT is not supported compression." && exit
    ;;
  esac
}
