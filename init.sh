#!/bin/bash

# ---------------------------------------
# command helpers
# ---------------------------------------

declare {HAS_VSCODE,HAS_PY}=false
BH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$BH_DIR/plugins/base.plugin.bash" # uses echo, test, md5, curl, tar, unzip, curl, rename, find
if type adb &>/dev/null; then source "$BH_DIR/aliases/adb.aliases.bash"; fi
if type apt &>/dev/null; then source "$BH_DIR/plugins/apt.plugin.bash"; fi
if type choco &>/dev/null; then source "$BH_DIR/plugins/choco.plugin.bash"; fi
if type cmake &>/dev/null; then source "$BH_DIR/plugins/cmake.plugin.bash"; fi
if type code &>/dev/null; then HAS_VSCODE=true; source "$BH_DIR/plugins/vscode.plugin.bash"; fi
if type deb &>/dev/null; then source "$BH_DIR/aliases/deb.aliases.bash"; fi
if type docker &>/dev/null; then source "$BH_DIR/plugins/docker.plugin.bash"; fi
if type ffmpeg &>/dev/null; then source "$BH_DIR/plugins/ffmpeg.plugin.bash"; fi
if type flutter &>/dev/null; then source "$BH_DIR/aliases/flutter.aliases.bash"; fi
if type gdb &>/dev/null; then source "$BH_DIR/plugins/gdb.aliases.bash"; fi
if type ghostscript &>/dev/null; then source "$BH_DIR/plugins/ghostscript.plugin.bash"; fi
if type git &>/dev/null; then source "$BH_DIR/plugins/git.plugin.bash"; fi
if type gnome-shell &>/dev/null; then source "$BH_DIR/plugins/gnome.plugin.bash"; fi
if type gst-launch-1.0 &>/dev/null; then source "$BH_DIR/plugins/gst.plugin.bash"; fi
if type lxc &>/dev/null; then source "$BH_DIR/plugins/lxc.plugin.bash"; fi
if type meson &>/dev/null; then source "$BH_DIR/plugins/meson.plugin.bash"; fi
if type pacman &>/dev/null; then source "$BH_DIR/plugins/pacman.plugin.bash"; fi
if type pandoc &>/dev/null; then source "$BH_DIR/plugins/pandoc.plugin.bash"; fi
if type pkg-config &>/dev/null; then source "$BH_DIR/plugins/pkg-config.plugin.bash"; fi
if type pngquant &>/dev/null; then source "$BH_DIR/plugins/pngquant.plugin.bash"; fi
if type python &>/dev/null; then HAS_PY=true; source "$BH_DIR/plugins/python.plugin.bash"; fi
if type ruby &>/dev/null; then source "$BH_DIR/plugins/ruby.plugin.bash"; fi
if type snap &>/dev/null; then source "$BH_DIR/aliases/snap.aliases.bash"; fi
if type ssh &>/dev/null; then source "$BH_DIR/plugins/ssh.plugin.bash"; fi
if type tesseract &>/dev/null; then source "$BH_DIR/plugins/tesseract.plugin.bash"; fi
if type youtube-dl &>/dev/null; then source "$BH_DIR/plugins/youtube-dl.plugin.bash"; fi

# ---------------------------------------
# OS helpers
# ---------------------------------------

case $OSTYPE in
linux*)
  if [[ $(uname -r) == *"icrosoft"* ]]; then # wsl
    source "$BH_DIR/aliases/wsl.aliases.bash"
    function wsl_update_clean() {
      bh_update_if_needed
      local pkgs="git deborphan apt-file vim diffutils curl "
      pkgs+="python3 python3-pip "
      apt_install $pkgs $BH_WSL_APT
      apt_autoremove
      $HAS_PY && py_set_v3_default
      $HAS_PY && py_install $BH_WSL_PY
      $HAS_PY && py_upgrade
      home_clean_unused
    }
  elif [[ $(lsb_release -d | awk '{print $2}') == Ubuntu ]]; then # ubu
    alias open="xdg-open"
    function ubu_update_clean() {
      bh_update_if_needed
      local pkgs="git deborphan apt-file vim diffutils curl "
      pkgs+="python3 python3-pip "
      apt_install $pkgs $BH_UBU_APT
      apt_autoremove
      apt_upgrade
      $HAS_PY && py_install $BH_UBU_PY
      $HAS_PY && py_upgrade
      $HAS_VSCODE && vscode_install $BH_UBU_VSCODE
      home_clean_unused
    }
  fi
  ;;

msys*)
  source "$BH_DIR/plugins/win.plugin.bash"
  if type gsudo &>/dev/null; then HAS_GSUDO=true; else HAS_GSUDO=false; fi
  function win_update_clean() {
    bh_update_if_needed
    home_clean_unused
    explorer_hide_home_dotfiles
    $HAS_PY && py_install $BH_WIN_PY
    $HAS_PY && py_upgrade
    $HAS_VSCODE && vscode_install $BH_WIN_VSCODE
    $HAS_GSUDO && win_sysupdate
    # winget (it uses --scope=user)
    win_get_install $BH_WIN_GET
  }
  function msys_fix_home() {
    if ! test -d /mnt/; then mkdir /mnt/; fi
    echo -e "none / cygdrive binary,posix=0,noacl,user 0 0" | tee /etc/fstab
    echo -e "C:/Users /home ntfs binary,noacl,auto 1 1" | tee -a /etc/fstab
    echo -e "C:/Users /Users ntfs binary,noacl,auto 1 1" | tee -a /etc/fstab
    # use /mnt/c/ like in WSL
    echo -e "/c /mnt/c none bind" | tee -a /etc/fstab
    echo -e 'db_home: windows >> /etc/nsswitch.conf' | tee -a /etc/nsswitch.conf
  }
  function msys_update_clean() {
    bh_update_if_needed
    # essentials
    local pkgs="pacman pacman-mirrors msys2-runtime vim diffutils curl $BH_MSYS_PAC"
    pacman_install $pkgs
    pacman --needed -S bash pacman pacman-mirrors msys2-runtime
    pacman -Su --noconfirm
    $HAS_PY && py_install $BH_MSYS_PY
    $HAS_PY && py_upgrade
    home_clean_unused
  }
  ;;

darwin*)
  function mac_update_clean() {
    bh_update_if_needed
    # brew
    local pkgs="git bash vim diffutils curl "
    pkgs+="python3 python-pip "
    brew update
    sudo brew upgrade
    brew install $pkgs $BH_MAC_BREW
    $HAS_PY && py_install $BH_MAC_PY
    $HAS_PY && py_upgrade
    $HAS_VSCODE && vscode_install $BH_MAC_VSCODE
    home_clean_unused
  }
  ;;
esac
