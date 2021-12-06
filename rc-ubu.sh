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

if type gnome-shell &>/dev/null; then
  source "$BH_DIR/lib/ubu/gnome.sh"
fi
if type snap &>/dev/null; then
  source "$BH_DIR/lib/ubu/snap.sh"
fi
if type service &>/dev/null; then source "$BH_DIR/lib/ubu/initd.sh"; fi
if type lxc &>/dev/null; then source "$BH_DIR/lib/ubu/lxc.sh"; fi
if type lsof &>/dev/null; then source "$BH_DIR/lib/ubu/ports.sh"; fi
if type systemctl &>/dev/null; then source "$BH_DIR/lib/ubu/systemd.sh"; fi

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
  local pkgs="git deborphan apt-file vim diffutils curl "
  # python
  pkgs+="python3 python3-pip "
  bh_apt_install $pkgs
  # set python3 as default
  bh_python_set_python3_default
  # apt
  bh_apt_install $BH_PKGS_APT_UBUNTU
  bh_apt_autoremove
  bh_apt_upgrade
  # python
  $HAS_PYTHON && bh_python_install $BH_PKGS_PYTHON
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
