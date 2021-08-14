# ---------------------------------------
# diff helpers
# ---------------------------------------

function bh_diff() {
  : ${2?"Usage: ${FUNCNAME[0]} <old_file> <new_file>"}
  diff "$1" "$2"
}

function bh_diff_apply() {
  : ${2?"Usage: ${FUNCNAME[0]} <patch> <targed_file>"}
  patch apply "$1" "$2"
}
