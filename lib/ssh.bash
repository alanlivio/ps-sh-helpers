# ---------------------------------------
# ssh
# ---------------------------------------

function bh_ssh_fix_permissions() {
  chmod 700 $HOME/.ssh/
  if test -e $HOME/.ssh/id_rsa; then
    chmod 600 $HOME/.ssh/id_rsa
    chmod 640 $HOME/.ssh/id_rsa.pubssh-rsa
  fi
}

function bh_ssh_send_keys_to_server() {
  : ${1?"Usage: ${FUNCNAME[0]} <user@server>"}
  ssh-copy-id -i ~/.ssh/id_rsa.pub $1
}

function bh_ssh_send_keys_to_server_old() {
  : ${1?"Usage: ${FUNCNAME[0]} <user@server>"}
  ssh "$1" sh -c 'cat - >> $HOME/.ssh/authorized_keys' <$HOME/.ssh/id_rsa.pub
}
