# ---------------------------------------
# helpers helpers
# ---------------------------------------
function bh_compress_zip_files() {
  : ${2?"Usage: ${FUNCNAME[0]} <zip-name> <files... >"}
  zipname=$1
  shift
  zip "$zipname" -r "$@"
}

function bh_compress_zip_folder() {
  : ${1?"Usage: ${FUNCNAME[0]} <folder-name>"}
  zip "$(basename $1).zip" -r $1
}