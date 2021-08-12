# ---------------------------------------
# rename helpers
# ---------------------------------------

function bh_rename_to_lowercase_with_underscore() {
  : ${1?"Usage: ${FUNCNAME[0]} <file_name>"}
  echo "rename to lowercase with underscore"
  rename 'y/A-Z/a-z/' "$@"
  echo "replace '.', ' ', and '-' by '_''"
  rename 's/-+/_/g;s/\.+/_/g;s/ +/_/g' "$@"
}

function bh_rename_to_lowercase_with_dash() {
  : ${1?"Usage: ${FUNCNAME[0]} <file_name>"}
  echo "rename to lowercase with dash"
  rename 'y/A-Z/a-z/' "$@"
  echo "replace '.', ' ', and '-' by '_''"
  rename 's/_+/-/g;s/\.+/-/g;s/ +/-/g' "$@"
}
