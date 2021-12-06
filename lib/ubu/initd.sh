# ---------------------------------------
# initd
# ---------------------------------------

function bh_ubu_initd_list() {
  service --status-all
}

function bh_ubu_initd_enable() {
  : ${1?"Usage: ${FUNCNAME[0]} <script_file>"}$1
  sudo update-rc.d $1 enable
}

function bh_ubu_initd_disable() {
  : ${1?"Usage: ${FUNCNAME[0]} <script_file>"}$1
  sudo service $1 stop
  sudo update-rc.d -f $1 disable
}