function hf_snap_install() {
  hf_log_func
  hf_test_noargs_then_return

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

function hf_snap_install_classic() {
  hf_log_func
  hf_test_noargs_then_return

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

function hf_snap_install_edge() {
  hf_log_func
  hf_test_noargs_then_return

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

function hf_snap_upgrade() {
  hf_log_func
  sudo snap refresh 2>/dev/null
}

function hf_snap_hide_home_folder() {
  echo snap >>$HOME/.hidden
}
