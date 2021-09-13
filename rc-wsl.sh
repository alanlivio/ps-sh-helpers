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
# load commands for windows
# ---------------------------------------

source "$BH_DIR/win/user.sh" # bh_user_win_check_admin
source "$BH_DIR/win/install.sh"
source "$BH_DIR/win/winget.sh"
source "$BH_DIR/win/explorer.sh"

# ---------------------------------------
# load commands for ubuntu
# ---------------------------------------
source "$BH_DIR/rc-ubuntu.sh"

# ---------------------------------------
# update_clean
# ---------------------------------------

function bh_update_cleanup_wsl() {
  # windows
  if [ "$(bh_user_win_check_admin)" == "True" ]; then
    bh_syswin_update_win
  fi
  # essentials
  local pkgs="git deborphan apt-file vim diffutils curl "
  # python
  pkgs+="python3-pip "
  bh_apt_install $pkgs
  # set python3 as default
  bh_python_set_python3_default
  # apt
  bh_apt_install $BH_PKGS_APT_WSL
  bh_apt_autoremove
  # python
  $HAS_PYTHON && bh_python_install $BH_PKGS_PYTHON
  # cleanup
  bh_home_clean_unused
}

# ---------------------------------------
# wsl_install
# ---------------------------------------

function bh_install_wsl_lxc() {
  # https://www.youtube.com/watch?v=SLDrvGUksv0
  sudo apt install lxd snap
  sudo apt-get install -yqq daemonize dbus-user-session fontconfig
  sudo daemonize /usr/bin/unshare --fork --pid --mount-proc /lib/systemd/systemd --system-unit=basic.target
  sudo nsenter -t $(pidof systemd) -a su - $LOGNAME
  sudo snap install lxd
}

function bh_install_wsl_ssh() {
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

# ---------------------------------------
# xpulseaudio
# ---------------------------------------

if [ "$(bh_user_win_check_admin)" == "True" ]; then

  function bh_wsl_xpulseaudio_enable() {
    bh_choco_install "pulseaudio vcxsrv"

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

  function bh_wsl_xpulseaudio_start() {
    bh_wsl_xpulseaudio_stop
    $(unixpath C:\\ProgramData\\chocolatey\\bin\\pulseaudio.exe) &
    "$(unixpath 'C:\Program Files\VcXsrv\vcxsrv.exe')" :0 -multiwindow -clipboard -wgl -ac -silent-dup-error &
  }

  function bh_wsl_xpulseaudio_stop() {
    cmd.exe /c "taskkill /IM pulseaudio.exe /F"
    cmd.exe /c "taskkill /IM vcxsrv.exe /F"
  }
fi
