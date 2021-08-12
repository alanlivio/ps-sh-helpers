function bh_snap_install() {
  bh_log_func

  local pkgs_installed="$(snap list | awk 'NR>1 {print $1}')"
  local pkgs_to_install=""
  for i in "$@"; do
    echo "$pkgs_installed" | grep "^$i" &>/dev/null
    if test $? != 0; then
      pkgs_to_install="$pkgs_to_install $i"
    fi
  done
  if test ! -z "$pkgs_to_install"; then
    echo "pkgs_to_install=$pkgs_to_install"
    for i in $pkgs_to_install; do
      sudo snap install "$i"
    done
  fi
}

function bh_snap_install_classic() {
  bh_log_func

  local pkgs_installed="$(snap list | awk 'NR>1 {print $1}')"
  local pkgs_to_install=""
  for i in "$@"; do
    echo "$pkgs_installed" | grep "^$i" &>/dev/null
    if test $? != 0; then
      pkgs_to_install="$pkgs_to_install $i"
    fi
  done
  if test ! -z "$pkgs_to_install"; then
    echo "pkgs_to_install=$pkgs_to_install"
    for i in $pkgs_to_install; do
      sudo snap install --classic "$i"
    done
  fi
}

function bh_snap_install_edge() {
  bh_log_func

  local pkgs_installed="$(snap list | awk 'NR>1 {print $1}')"
  local pkgs_to_install=""
  for i in "$@"; do
    echo "$pkgs_installed" | grep "^$i" &>/dev/null
    if test $? != 0; then
      pkgs_to_install="$pkgs_to_install $i"
    fi
  done
  if test ! -z "$pkgs_to_install"; then
    echo "pkgs_to_install=$pkgs_to_install"
    for i in $pkgs_to_install; do
      sudo snap install --edge "$i"
    done
  fi
}

function bh_snap_upgrade() {
  bh_log_func
  sudo snap refresh 2>/dev/null
}

function bh_snap_hide_home_folder() {
  echo snap >>$HOME/.hidden
}
