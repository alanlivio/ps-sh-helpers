# ---------------------------------------
# alias
# ---------------------------------------
alias unixpath='wslpath'
alias winpath='wslpath -w'
# fix writting permissions
if [[ "$(umask)" = "0000" ]]; then
  umask 0022
fi

# ---------------------------------------
# load libs for specific commands
# ---------------------------------------

IS_GNOME=false
HAS_SNAP=false
if type gnome-shell &>/dev/null; then IS_GNOME=true; fi
if type snap &>/dev/null; then HAS_SNAP=true; fi
if $IS_GNOME; then source "$BH_DIR/ubuntu/gnome.sh"; fi
if $HAS_SNAP; then source "$BH_DIR/ubuntu/snap.sh"; fi
if type apt tar &>/dev/null; then source "$BH_DIR/ubuntu/apt.sh"; fi
if type systemctl tar &>/dev/null; then source "$BH_DIR/ubuntu/systemd.sh"; fi
if type service tar &>/dev/null; then source "$BH_DIR/ubuntu/initd.sh"; fi
if type lxc &>/dev/null; then source "$BH_DIR/ubuntu/lxc.sh"; fi
if type lsof &>/dev/null; then source "$BH_DIR/ubuntu/ports.sh"; fi

# ---------------------------------------
# update_clean helper
# ---------------------------------------

function bh_update_clean_wsl() {
  # essentials
  local pkgs="git deborphan apt-file $BH_PKGS_ESSENTIALS "
  # python
  pkgs+="python3-pip "
  bh_apt_install $pkgs
  # set python3 as default
  bh_python_set_python3_default
  # apt
  bh_apt_install $PKGS_APT
  bh_apt_remove_pkgs $PKGS_REMOVE_APT
  bh_apt_autoremove
  bh_apt_remove_orphan_pkgs $PKGS_APT_ORPHAN_EXPECTIONS
  # python
  bh_python_upgrade
  bh_python_install $PKGS_PYTHON
  # cleanup
  bh_home_clean_unused
}

# ---------------------------------------
# wsl_install helpers
# ---------------------------------------

function bh_wsl_install_lxc() {
  # https://www.youtube.com/watch?v=SLDrvGUksv0
  sudo apt install lxd snap
  sudo apt-get install -yqq daemonize dbus-user-session fontconfig
  sudo daemonize /usr/bin/unshare --fork --pid --mount-proc /lib/systemd/systemd --system-unit=basic.target
  sudo nsenter -t $(pidof systemd) -a su - $LOGNAME
  sudo snap install lxd
}

function bh_wsl_install_ssh() {
  sudo apt install -y openssh-server
  # https://github.com/JetBrains/clion-wsl/blob/master/ubuntu_setup_env.sh
  local sshd_listen_address=127.0.0.1
  local sshd_port=2222
  local sshd_file=/etc/ssh/sshd_config
  local sudoers_file=/etc/sudoers
  sudo apt install -y openssh-server
  sudo cp $sshd_file ${sshd_file}.$(date '+%Y-%m-%d_%H-%M-%S').back
  sudo sed -i '/^Port/ d' $sshd_file
  sudo sed -i '/^ListenAddress/ d' $sshd_file
  sudo sed -i '/^UsePrivilegeSeparation/ d' $sshd_file
  sudo sed -i '/^PasswordAuthentication/ d' $sshd_file
  echo "# configured by CLion" | sudo tee -a $sshd_file
  echo "ListenAddress ${sshd_listen_address}" | sudo tee -a $sshd_file
  echo "Port ${sshd_port}" | sudo tee -a $sshd_file
  echo "PasswordAuthentication yes" | sudo tee -a $sshd_file
  echo "%sudo ALL=(ALL) NOPASSWD: /usr/sbin/service ssh --full-restart" | sudo tee -a $sudoers_file
  sudo service ssh --full-restart
}
