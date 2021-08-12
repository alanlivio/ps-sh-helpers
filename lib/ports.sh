function hf_ports_list() {
  lsof -i
}

function hf_ports_kill_using() {
  : ${1?"Usage: ${FUNCNAME[0]} <port>"}
  pid=$(sudo lsof -t -i:$1)
  if test -n "$pid"; then
    sudo kill -9 "$pid"
  fi
}

function hf_ports_list_one() {
  : ${1?"Usage: ${FUNCNAME[0]} <port>"}
  sudo lsof -i:$1
}
