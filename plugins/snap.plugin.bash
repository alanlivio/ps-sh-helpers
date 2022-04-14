function ubu_snap_install() {
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

function ubu_snap_install_classic() {
  local pkgs_installed="$(snap list | awk 'NR>1 {print $1}')"
  local pkgs_to_install=""
  for i in "$@"; do
    if [[ ! $pkgs_installed =~ $i ]]; then
      pkgs_to_install="$i $pkgs_to_install"
    fi
  done
  if test ! -z "$pkgs_to_install"; then
    log_msg "pkgs_to_install=$pkgs_to_install"
    for i in $pkgs_to_install; do
      sudo snap install --classic "$i"
    done
  fi
}

function ubu_snap_install_edge() {
  local pkgs_installed="$(snap list | awk 'NR>1 {print $1}')"
  local pkgs_to_install=""
  for i in "$@"; do
    if [[ ! $pkgs_installed =~ $i ]]; then
      pkgs_to_install="$i $pkgs_to_install"
    fi
  done
  if test ! -z "$pkgs_to_install"; then
    log_msg "pkgs_to_install=$pkgs_to_install"
    for i in $pkgs_to_install; do
      sudo snap install --edge "$i"
    done
  fi
}

function ubu_snap_upgrade() {
  sudo snap refresh 2>/dev/null
}

function ubu_snap_hide_home_dir() {
  echo snap >>$HOME/.hidden
}
