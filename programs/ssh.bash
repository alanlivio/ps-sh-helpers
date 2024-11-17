function ssh_send_to_server_authorized_pub_key() {
    : ${1?"Usage: ${FUNCNAME[0]} <user@server>"}
    ssh "$1" sh -c 'cat - >> ~/.ssh/authorized_keys' <$HOME/.ssh/id_rsa.pub
}

function ssh_send_to_server_priv_key() {
    : ${1?"Usage: ${FUNCNAME[0]} <user@server>"}
    ssh "$1" sh -c 'cat - > ~/.ssh/id_rsa;chmod 600 $HOME/.ssh/id_rsa' <$HOME/.ssh/id_rsa
}
