# ---------------------------------------
# log
# ---------------------------------------

alias bh_log_func='bh_log_msg "${FUNCNAME[0]}"'
alias bh_log_not_implemented_return="bh_log_error 'Not implemented'; return;"

function bh_log_wrap() {
  echo -e "$1" | fold -w100 -s
}

function bh_log_error() {
  bh_log_wrap "\033[00;31m-- $* \033[00m"
}

function bh_log_msg() {
  bh_log_wrap "\033[00;33m-- $* \033[00m"
}

function bh_log_msg_2nd() {
  bh_log_wrap "\033[00;33m-- > $* \033[00m"
}

function bh_log_done() {
  bh_log_wrap "\033[00;32m-- done\033[00m"
}

function bh_log_ok() {
  bh_log_wrap "\033[00;32m-- ok\033[00m"
}

function bh_log_try() {
  "$@"
  if $? -ne 0; then bh_log_error "$1" && exit 1; fi
}

# ---------------------------------------
# test
# ---------------------------------------

function bh_test_and_create_folder() {
  if test ! -d $1; then
    bh_log_msg "creating $1"
    mkdir -p $1
  fi
}

function bh_test_and_create_file() {
  : ${1?"Usage: ${FUNCNAME[0]} [file]"}
  if ! test -f "$1"; then
    bh_test_and_create_folder $(dirname $1)
    touch "$1"
  fi
}

function bh_test_and_delete_dir() {
  if test -d $1; then rm -rf $1; fi
}