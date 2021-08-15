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
if $IS_GNOME; then source "$BH_DIR/lib-ubuntu/gnome.sh"; fi
if $HAS_SNAP; then source "$BH_DIR/lib-ubuntu/snap.sh"; fi
if type apt tar &>/dev/null; then source "$BH_DIR/lib-ubuntu/apt.sh"; fi
if type systemctl tar &>/dev/null; then source "$BH_DIR/lib-ubuntu/systemd.sh"; fi
if type service tar &>/dev/null; then source "$BH_DIR/lib-ubuntu/initd.sh"; fi
if type lxc &>/dev/null; then source "$BH_DIR/lib-ubuntu/lxc.sh"; fi
if type lsof &>/dev/null; then source "$BH_DIR/lib-ubuntu/ports.sh"; fi

# ---------------------------------------
# setup/update_clean helpers
# ---------------------------------------

function bh_wsl_setup() {
  # sudo nopasswd
  bh_user_permissions_sudo_nopasswd
  # essentials
  local pkgs="git deborphan apt-file $PKGS_ESSENTIALS "
  # python
  pkgs+="python3-pip "
  bh_apt_install $pkgs
  # set python3 as default
  bh_python_set_python3_default
}

function bh_wsl_update_clean() {
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
# x_pulseaudio helpers
# ---------------------------------------

function bh_wsl_x_pulseaudio_enable() {
  bh_ps_call_admin "bh_choco_install pulseaudio vcxsrv"

  # https://wiki.ubuntu.com/WSL#Running_Graphical_Applications
  sudo apt-get install pulseaudio
  echo -e "load-module module-native-protocol-tcp auth-anonymous=1" | sudo "sudo tee -a $(unixpath C:\\ProgramData\\chocolatey\\lib\\pulseaudio\\tools\\etc\\pulse\\default.pa)"
  echo -e "exit-idle-time = -1" | sudo "sudo tee -a $(unixpath C:\\ProgramData\\chocolatey\\lib\\pulseaudio\\tools\\etc\\pulse\\daemon.conf)"

  # configure .profile
  if ! grep -q "PULSE_SERVER" $HOME/.profile; then
    echo -e "\nexport DISPLAY=\"$(awk '/nameserver / {print $2; exit}' /etc/resolv.conf 2>/dev/null):0\"" | tee -a $HOME/.profile
    echo "export PULSE_SERVER=\"$(awk '/nameserver / {print $2; exit}' /etc/resolv.conf 2>/dev/null):0\"" | tee -a $HOME/.profile
    echo "export LIBGL_ALWAYS_INDIRECT=1" | tee -a $HOME/.profile
  fi
}

function bh_wsl_x_pulseaudio_start() {
  bh_wsl_x_pulseaudio_kill
  $(unixpath C:\\ProgramData\\chocolatey\\bin\\pulseaudio.exe) &
  "$(unixpath 'C:\Program Files\VcXsrv\vcxsrv.exe')" :0 -multiwindow -clipboard -wgl -ac -silent-dup-error &
}

function bh_wsl_x_pulseaudio_stop() {
  cmd.exe /c "taskkill /IM pulseaudio.exe /F"
  cmd.exe /c "taskkill /IM vcxsrv.exe /F"
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
  SSHD_LISTEN_ADDRESS=127.0.0.1
  SSHD_PORT=2222
  SSHD_FILE=/etc/ssh/sshd_config
  SUDOERS_FILE=/etc/sudoers
  sudo apt install -y openssh-server
  sudo cp $SSHD_FILE ${SSHD_FILE}.$(date '+%Y-%m-%d_%H-%M-%S').back
  sudo sed -i '/^Port/ d' $SSHD_FILE
  sudo sed -i '/^ListenAddress/ d' $SSHD_FILE
  sudo sed -i '/^UsePrivilegeSeparation/ d' $SSHD_FILE
  sudo sed -i '/^PasswordAuthentication/ d' $SSHD_FILE
  echo "# configured by CLion" | sudo tee -a $SSHD_FILE
  echo "ListenAddress ${SSHD_LISTEN_ADDRESS}" | sudo tee -a $SSHD_FILE
  echo "Port ${SSHD_PORT}" | sudo tee -a $SSHD_FILE
  echo "PasswordAuthentication yes" | sudo tee -a $SSHD_FILE
  echo "%sudo ALL=(ALL) NOPASSWD: /usr/sbin/service ssh --full-restart" | sudo tee -a $SUDOERS_FILE
  sudo service ssh --full-restart
}
