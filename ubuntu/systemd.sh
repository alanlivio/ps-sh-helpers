# ---------------------------------------
# systemd
# ---------------------------------------

function bh_systemd_list() {
  systemctl --type=service
}

function bh_systemd_status_service() {
  : ${1?"Usage: ${FUNCNAME[0]} <service_name>"}
  systemctl status $1
}

function bh_systemd_add_script() {
  : ${1?"Usage: ${FUNCNAME[0]} <service_file>"}
  systemctl daemon-reload
  systemctl enable $1
}
