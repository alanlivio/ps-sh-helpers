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
# update_clean
# ---------------------------------------

unset bh_update_cleanup_ubu
function bh_update_cleanup_wsl() {
  # essentials
  local pkgs="git deborphan apt-file vim diffutils curl "
  # python
  pkgs+="python3-pip "
  bh_ubu_apt_install $pkgs
  # set python3 as default
  bh_python_set_python3_default
  # apt
  bh_ubu_install $BH_PKGS_APT_WSL
  bh_ubu_autoremove
  # python
  $HAS_PYTHON && bh_python_install $BH_PKGS_PYTHON
  # cleanup
  bh_home_clean_unused
}

# ---------------------------------------
# wsl_install
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