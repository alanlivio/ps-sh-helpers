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

function bh_wsl_fix_snap_lxc() {
  # https://www.youtube.com/watch?v=SLDrvGUksv0
  sudo apt install lxd snap
  sudo apt-get install -yqq daemonize dbus-user-session fontconfig
  sudo daemonize /usr/bin/unshare --fork --pid --mount-proc /lib/systemd/systemd --system-unit=basic.target
  sudo nsenter -t $(pidof systemd) -a su - $LOGNAME
  sudo snap install lxd
}

function bh_wsl_ssh_config() {
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

function bh_wsl_ssh_start() {
  sshd_status=$(service ssh status)
  if [[ $sshd_status = *"is not running"* ]]; then
    sudo service ssh --full-restart
  fi
}

function bh_setup_wsl() {
  # sudo nopasswd
  bh_user_permissions_sudo_nopasswd
  # essentials
  PKGS="git deborphan apt-file $PKGS_ESSENTIALS "
  # python
  PKGS+="python3-pip "
  bh_apt_install $PKGS
  # set python3 as default
  bh_python_set_python3_default
}
