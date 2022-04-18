#!/bin/bash

# ---------------------------------------
# command helpers
# ---------------------------------------

BH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$BH_DIR/plugins/base.plugin.bash" # uses echo, test, md5, curl, tar, unzip, curl, rename, find
if [[ $OSTYPE == "msys" ]]; then source "$BH_DIR/plugins/win.plugin.bash"; fi
if type adb &>/dev/null; then source "$BH_DIR/aliases/adb.aliases.bash"; fi
if type apt &>/dev/null; then source "$BH_DIR/plugins/apt.plugin.bash"; fi
if type choco &>/dev/null; then source "$BH_DIR/plugins/choco.plugin.bash"; fi
if type cmake &>/dev/null; then source "$BH_DIR/plugins/cmake.plugin.bash"; fi
if type code &>/dev/null; then source "$BH_DIR/plugins/vscode.plugin.bash"; fi
if type deb &>/dev/null; then source "$BH_DIR/aliases/deb.aliases.bash"; fi
if type docker &>/dev/null; then source "$BH_DIR/plugins/docker.plugin.bash"; fi
if type ffmpeg &>/dev/null; then source "$BH_DIR/plugins/ffmpeg.plugin.bash"; fi
if type flutter &>/dev/null; then source "$BH_DIR/aliases/flutter.aliases.bash"; fi
if type gdb &>/dev/null; then source "$BH_DIR/plugins/gdb.aliases.bash"; fi
if type ghostscript &>/dev/null; then source "$BH_DIR/plugins/ghostscript.plugin.bash"; fi
if type git &>/dev/null; then source "$BH_DIR/plugins/git.plugin.bash"; fi
if type gnome-shell &>/dev/null; then source "$BH_DIR/plugins/gnome.plugin.bash"; fi
if type gst-launch-1.0 &>/dev/null; then source "$BH_DIR/plugins/gst.plugin.bash"; fi
if type gsudo &>/dev/null; then HAS_GSUDO=true; else HAS_GSUDO=false; fi
if type lxc &>/dev/null; then source "$BH_DIR/plugins/lxc.plugin.bash"; fi
if type meson &>/dev/null; then source "$BH_DIR/plugins/meson.plugin.bash"; fi
if type pacman &>/dev/null; then source "$BH_DIR/plugins/pacman.plugin.bash"; fi
if type pandoc &>/dev/null; then source "$BH_DIR/plugins/pandoc.plugin.bash"; fi
if type pkg-config &>/dev/null; then source "$BH_DIR/plugins/pkg-config.plugin.bash"; fi
if type pngquant &>/dev/null; then source "$BH_DIR/plugins/pngquant.plugin.bash"; fi
if type python &>/dev/null; then source "$BH_DIR/plugins/python.plugin.bash"; fi
if type ruby &>/dev/null; then source "$BH_DIR/plugins/ruby.plugin.bash"; fi
if type snap &>/dev/null; then source "$BH_DIR/aliases/snap.aliases.bash"; fi
if type ssh &>/dev/null; then source "$BH_DIR/plugins/ssh.plugin.bash"; fi
if type tesseract &>/dev/null; then source "$BH_DIR/plugins/tesseract.plugin.bash"; fi
if type youtube-dl &>/dev/null; then source "$BH_DIR/plugins/youtube-dl.plugin.bash"; fi

# ---------------------------------------
# OS helpers
# ---------------------------------------

function setup_os() {

  case $OSTYPE in
  linux*) # wsl/ubu
    local pkgs="git deborphan apt-file vim diffutils curl python3 python3-pip "
    if [[ $(uname -r) == *"icrosoft"* ]]; then
        apt_install $pkgs $BH_WSL_APT
        py_install $BH_WSL_PY
    elif [[ $(lsb_release -d | awk '{print $2}') == Ubuntu ]]; then
      apt_install $pkgs $BH_UBU_APT
      py_install $BH_UBU_PY
    fi
    apt_upgrade
    apt_autoremove
    py_upgrade
    home_clean_unused
    ;;

  msys*)
    if test -e /etc/profile.d/git-prompt.sh; then
      echo  "in gitbash"
      py_install $BH_WIN_PY
      $HAS_GSUDO && win_sysupdate
      win_get_install $BH_WIN_GET  # winget (it uses --scope=user)
    else
      local pkgs="bash pacman pacman-mirrors msys2-runtime vim diffutils curl "
      pacman_install $pkgs $BH_MSYS_PAC
      py_install $BH_MSYS_PY
    fi
    explorer_hide_home_dotfiles
    py_upgrade
    home_clean_unused
    ;;

  darwin*)
      local pkgs="git bash vim diffutils curl "
      pkgs+="python3 python-pip "
      brew update
      sudo brew upgrade
      brew install $pkgs $BH_MAC_BREW
      py_install $BH_MAC_PY
      py_upgrade
      home_clean_unused
    ;;
  esac
}
