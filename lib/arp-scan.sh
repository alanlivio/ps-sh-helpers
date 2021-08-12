function hf_arp_scan() {
  sudo arp-scan --localnet
}

function hf_arp_scan_for_interface() {
  : ${1?"Usage: ${FUNCNAME[0]} <network_interface>"}
  sudo arp-scan --localnet --interface=$1
}
