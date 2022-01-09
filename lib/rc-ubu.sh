# ---------------------------------------
# ubuntu aliases
# ---------------------------------------

function bh_open {
  local node="${1:-.}" # . is default value
  xdg-open $node
}

# ---------------------------------------
# load commands
# ---------------------------------------

source "$BH_DIR/lib/ubu/install.sh"
if type gnome-shell &>/dev/null; then source "$BH_DIR/lib/ubu/gnome.sh"; fi
if type lxc &>/dev/null; then source "$BH_DIR/lib/ubu/lxc.sh"; fi
if type snap &>/dev/null; then source "$BH_DIR/lib/ubu/snap.sh"; fi

# ---------------------------------------
# update_clean
# ---------------------------------------

function bh_update_cleanup_ubu() {
  if type snap &>/dev/null; then
    # snap
    bh_snap_install $BH_PKGS_SNAP
    bh_snap_install_classic $BH_PKGS_SNAP_CLASSIC
    bh_snap_upgrade
  fi
  # apt
  local pkgs="git deborphan apt-file vim diffutils curl "
  pkgs+="python3 python3-pip "
  bh_apt_install $pkgs $BH_PKGS_APT_UBUNTU
  bh_apt_autoremove
  bh_apt_upgrade
  # py
  bh_py_set_v3_default
  $HAS_PYTHON && bh_py_install $BH_PKGS_PY
  # vscode
  $HAS_VSCODE && bh_vscode_install $BH_PKGS_VSCODE
  # cleanup
  bh_home_clean_unused
}

# ---------------------------------------
# ubuntu_server
# ---------------------------------------

function bh_ubu_server_tty1_autologing() {
  local file="/etc/systemd/system/getty@tty1.service.d/override.conf"
  sudo mkdir -p $(dirname $file)
  sudo touch $file
  echo '[Service]' | sudo tee $file
  echo 'ExecStart=' | sudo tee -a $file
  echo "ExecStart=-/sbin/agetty --noissue --autologin $USER %I $TERM" | sudo tee -a $file
  echo 'Type=idle' | sudo tee -a $file
}

# ---------------------------------------
# systemd
# ---------------------------------------

function bh_ubu_systemd_list() {
  systemctl --type=service
}

function bh_ubu_systemd_status_service() {
  : ${1?"Usage: ${FUNCNAME[0]} <service_name>"}
  systemctl status $1
}

function bh_ubu_systemd_add_script() {
  : ${1?"Usage: ${FUNCNAME[0]} <service_file>"}
  systemctl daemon-reload
  systemctl enable $1
}

# ---------------------------------------
# ports
# ---------------------------------------

function bh_ubu_ports_list() {
  lsof -i
}

function bh_ubu_ports_kill_using() {
  : ${1?"Usage: ${FUNCNAME[0]} <port>"}
  local pid=$(sudo lsof -t -i:$1)
  if test -n "$pid"; then
    sudo kill -9 "$pid"
  fi
}

function bh_ubu_ports_list_one() {
  : ${1?"Usage: ${FUNCNAME[0]} <port>"}
  sudo lsof -i:$1
}

# ---------------------------------------
# deb
# ---------------------------------------

if type deb tar &>/dev/null; then
  function bh_ubu_deb_install() {
    : ${1?"Usage: ${FUNCNAME[0]} <pkg_name>"}
    sudo dpkg -i $1
  }

  function bh_ubu_deb_install_force_depends() {
    : ${1?"Usage: ${FUNCNAME[0]} <pkg_name>"}
    sudo dpkg -i --force-depends $1
  }

  function bh_ubu_deb_info() {
    : ${1?"Usage: ${FUNCNAME[0]} <pkg_name>"}
    dpkg-deb --info $1
  }

  function bh_ubu_deb_contents() {
    : ${1?"Usage: ${FUNCNAME[0]} <pkg_name>"}
    dpkg-deb --show $1
  }
fi

# ---------------------------------------
# apt helpers
# ---------------------------------------

function bh_ubu_apt_upgrade() {
  bh_log_func
  sudo apt -y update
  if [ "$(apt list --upgradable 2>/dev/null | wc -l)" -gt 1 ]; then
    sudo apt -y upgrade
  fi
}

function bh_ubu_apt_update() {
  bh_log_func
  sudo apt -y update
}

function bh_ubu_apt_ppa_remove() {
  bh_log_func
  sudo add-apt-repository --remove $1
}

function bh_ubu_apt_ppa_list() {
  bh_log_func
  apt policy
}

function bh_ubu_apt_fixes() {
  bh_log_func
  sudo dpkg --configure -a
  sudo apt install -f --fix-broken
  sudo apt-get update --fix-missing
  sudo apt dist-upgrade
}

function bh_ubu_apt_install() {
  bh_log_func

  local pkgs_to_install=""
  for i in "$@"; do
    dpkg --status "$i" &>/dev/null
    if test $? != 0; then
      pkgs_to_install="$pkgs_to_install $i"
    fi
  done
  if test ! -z "$pkgs_to_install"; then
    bh_log_msg "pkgs_to_install=$pkgs_to_install"
    sudo apt install -y $pkgs_to_install
  fi
}

function bh_ubu_apt_lastest_pkgs() {
  local pkgs=""
  for i in "$@"; do
    pkgs+=$(apt search $i 2>/dev/null | grep -E -o "^$i([0-9.]+)/" | cut -d/ -f1)
    pkgs+=" "
  done
  echo $pkgs
}

function bh_ubu_apt_autoremove() {
  bh_log_func
  if [ "$(apt --dry-run autoremove 2>/dev/null | grep -c -Po 'Remv \K[^ ]+')" -gt 0 ]; then
    sudo apt -y autoremove
  fi
}

function bh_ubu_apt_remove_pkgs() {
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

function bh_ubu_apt_remove_orphan_pkgs() {
  local pkgs_orphan_to_remove=""
  while [ "$(deborphan | wc -l)" -gt 0 ]; do
    for i in $(deborphan); do
      local found_exception=false
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

function bh_ubu_apt_fetch_install() {
  : ${1?"Usage: ${FUNCNAME[0]} <URL>"}
  local apt_name=$(basename $1)
  if test ! -f /tmp/$apt_name; then
    bh_decompress_from_url $1 /tmp/
    if test $? != 0; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
  fi
  sudo dpkg -i /tmp/$apt_name
}

# ---------------------------------------
# distro
# ---------------------------------------

function bh_ubu_distro_upgrade() {
  sudo sed -i 's/Prompt=lts/Prompt=normal/g' /etc/update-manager/release-upgrades
  sudo apt update && sudo apt dist-upgrade
  do-release-upgrade
}
