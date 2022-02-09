# ---------------------------------------
# pkg-config
# ---------------------------------------

function bh_pkg_config_search() {
  : ${1?"Usage: ${FUNCNAME[0]} <pkg_name>"}
  pkg-config --list-all | grep --color=auto $1
}

function bh_pkg_config_show() {
  : ${1?"Usage: ${FUNCNAME[0]} <pkg_name>"}
  PKG=$(pkg-config --list-all | grep -w $1 | awk '{print $1;exit}')
  echo 'version:    '"$(pkg-config --modversion $PKG)"
  echo 'provides:   '"$(pkg-config --print-provides $PKG)"
  echo 'requireds:  '"$(pkg-config --print-requires $PKG | awk '{print}' ORS=' ')"
}
