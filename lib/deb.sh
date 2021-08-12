# ---------------------------------------
# deb
# ---------------------------------------

function bh_deb_install() {
  : ${1?"Usage: ${FUNCNAME[0]} <pkg_name>"}
  sudo dpkg -i $1
}

function bh_deb_install_force_depends() {
  : ${1?"Usage: ${FUNCNAME[0]} <pkg_name>"}
  sudo dpkg -i --force-depends $1
}

function bh_deb_info() {
  : ${1?"Usage: ${FUNCNAME[0]} <pkg_name>"}
  dpkg-deb --info $1
}

function bh_deb_contents() {
  : ${1?"Usage: ${FUNCNAME[0]} <pkg_name>"}
  dpkg-deb --show $1
}

# ---------------------------------------
# apt
# ---------------------------------------

function bh_apt_upgrade() {
  bh_log_func
  sudo apt -y update
  if [ "$(apt list --upgradable 2>/dev/null | wc -l)" -gt 1 ]; then
    sudo apt -y upgrade
  fi
}

function bh_apt_update() {
  bh_log_func
  sudo apt -y update
}

function bh_apt_ppa_remove() {
  bh_log_func
  sudo add-apt-repository --remove $1
}

function bh_apt_ppa_list() {
  bh_log_func
  apt policy
}

function bh_apt_fixes() {
  bh_log_func
  sudo dpkg --configure -a
  sudo apt install -f --fix-broken
  sudo apt-get update --fix-missing
  sudo apt dist-upgrade
}

function bh_apt_install() {
  bh_log_func

  local pkgs_to_install=""
  for i in "$@"; do
    dpkg --status "$i" &>/dev/null
    if test $? != 0; then
      pkgs_to_install="$pkgs_to_install $i"
    fi
  done
  if test ! -z "$pkgs_to_install"; then
    echo "pkgs_to_install=$pkgs_to_install"
  fi
  if test -n "$pkgs_to_install"; then
    sudo apt install -y $pkgs_to_install
  fi
}

function bh_apt_lastest_pkgs() {
  local pkgs=""
  for i in "$@"; do
    pkgs+=$(apt search $i 2>/dev/null | grep -E -o "^$i([0-9.]+)/" | cut -d/ -f1)
    pkgs+=" "
  done
  echo $pkgs
}

function bh_apt_autoremove() {
  bh_log_func
  if [ "$(apt --dry-run autoremove 2>/dev/null | grep -c -Po 'Remv \K[^ ]+')" -gt 0 ]; then
    sudo apt -y autoremove
  fi
}

function bh_apt_remove_pkgs() {
  bh_log_func
  local pkgs_to_remove=""
  for i in "$@"; do
    dpkg --status "$i" &>/dev/null
    if test $? -eq 0; then
      pkgs_to_remove="$pkgs_to_remove $i"
    fi
  done
  if test -n "$pkgs_to_remove"; then
    echo "pkgs_to_remove=$pkgs_to_remove"
    sudo apt remove -y --purge $pkgs_to_remove
  fi
}

function bh_apt_remove_orphan_pkgs() {
  local pkgs_orphan_to_remove=""
  while [ "$(deborphan | wc -l)" -gt 0 ]; do
    for i in $(deborphan); do
      found_exception=false
      for j in "$@"; do
        if test "$i" = "$j"; then
          found_exception=true
          return
        fi
      done
      if ! $found_exception; then
        pkgs_orphan_to_remove="$pkgs_orphan_to_remove $i"
      fi
    done
    echo "pkgs_orphan_to_remove=$pkgs_orphan_to_remove"
    if test -n "$pkgs_orphan_to_remove"; then
      sudo apt remove -y --purge $pkgs_orphan_to_remove
    fi
  done
}

function bh_apt_fetch_install() {
  : ${1?"Usage: ${FUNCNAME[0]} <URL>"}
  local apt_name=$(basename $1)
  if test ! -f /tmp/$apt_name; then
    wget --continue $1 -P /tmp/
    if test $? != 0; then bh_log_error "wget failed." && return 1; fi

  fi
  sudo dpkg -i /tmp/$apt_name
}
