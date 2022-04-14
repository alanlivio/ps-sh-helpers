#!/bin/bash

# ---------------------------------------
# OS vars
# ---------------------------------------

declare IS_{MAC,UBU,LINUX,WIN,WSL,MSYS,GITBASH}=false

case "$(uname -s)" in
CYGWIN* | MINGW* | MSYS*)
  IS_WIN=true
  if test -e /etc/profile.d/git-prompt.sh; then
    IS_GITBASH=true
  else
    IS_MSYS=true
  fi;;
Linux)
  IS_LINUX=true
  if [[ $(uname -r) == *"icrosoft"* ]]; then
    IS_WSL=true
  elif [[ $(lsb_release -d | awk '{print $2}') == Ubuntu ]]; then
    IS_UBU=true
  fi;;
Darwin)
  IS_MAC=true;;
esac

# ---------------------------------------
# specifc-commands helpers
# ---------------------------------------

BH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$BH_DIR/lib/base.bash" # uses echo, test, md5, curl, tar, unzip, curl, rename, find
if type code &>/dev/null; then HAS_VSCODE=true; source "$BH_DIR/lib/vscode.bash"; else HAS_VSCODE=false; fi
if type python &>/dev/null; then HAS_PY=true;source "$BH_DIR/lib/python.bash"; else HAS_PY=false; fi
if type choco &>/dev/null; then source "$BH_DIR/lib/choco.bash"; fi
if type deb &>/dev/null; then source "$BH_DIR/lib/deb.bash"; fi
if type adb &>/dev/null; then source "$BH_DIR/lib/adb.bash"; fi
if type cmake &>/dev/null; then source "$BH_DIR/lib/cmake.bash"; fi
if type docker &>/dev/null; then source "$BH_DIR/lib/docker.bash"; fi
if type ffmpeg &>/dev/null; then source "$BH_DIR/lib/ffmpeg.bash"; fi
if type flutter &>/dev/null; then source "$BH_DIR/lib/flutter.bash"; fi
if type gcc &>/dev/null; then source "$BH_DIR/lib/gcc.bash"; fi
if type ghostscript &>/dev/null; then source "$BH_DIR/lib/ghostscript.bash"; fi
if type git &>/dev/null; then source "$BH_DIR/lib/git.bash"; fi
if type gst-launch-1.0 &>/dev/null; then source "$BH_DIR/lib/gst.bash"; fi
if type meson &>/dev/null; then source "$BH_DIR/lib/meson.bash"; fi
if type pandoc &>/dev/null; then source "$BH_DIR/lib/pandoc.bash"; fi
if type pngquant &>/dev/null; then source "$BH_DIR/lib/pngquant.bash"; fi
if type pdflatex &>/dev/null; then source "$BH_DIR/lib/pdflatex.bash"; fi
if type pkg-config &>/dev/null; then source "$BH_DIR/lib/pkg-config.bash"; fi
if type ruby &>/dev/null; then source "$BH_DIR/lib/ruby.bash"; fi
if type ssh &>/dev/null; then source "$BH_DIR/lib/ssh.bash"; fi
if type tesseract &>/dev/null; then source "$BH_DIR/lib/tesseract.bash"; fi
if type wget &>/dev/null; then source "$BH_DIR/lib/wget.bash"; fi
if type youtube-dl &>/dev/null; then source "$BH_DIR/lib/youtube-dl.bash"; fi
if type zip &>/dev/null; then source "$BH_DIR/lib/zip.bash"; fi
if type gnome-shell &>/dev/null; then source "$BH_DIR/lib/gnome.bash"; fi
if type lxc &>/dev/null; then source "$BH_DIR/lib/lxc.bash"; fi
if type apt &>/dev/null; then source "$BH_DIR/lib/apt.bash"; fi
if type brew &>/dev/null; then source "$BH_DIR/lib/brew.bash"; fi
if type snap &>/dev/null; then source "$BH_DIR/lib/snap.bash"; fi
if type pacman &>/dev/null; then source "$BH_DIR/lib/pacman.bash"; fi

# ---------------------------------------
# OS helpers
# ---------------------------------------

if $IS_GITBASH; then
  source "$BH_DIR/lib/win.bash"
  function win_update_clean() {
    log_func
    # update bh
    update_if_needed
    # cleanup
    home_clean_unused
    win_explorer_hide_home_dotfiles
    # py
    $HAS_PY && py_install $BH_WIN_PY
    $HAS_PY && py_upgrade
    # vscode
    $HAS_VSCODE && vscode_install $BH_WIN_VSCODE
    # win
    $HAS_GSUDO && win_sysupdate_win
    # winget (it uses --scope=user)
    win_get_install $BH_WIN_GET
  }
elif $IS_WSL; then
  source "$BH_DIR/lib/wsl.bash"
  function wsl_update_clean() {
    log_func
    # update bh
    update_if_needed
    # apt
    local pkgs="git deborphan apt-file vim diffutils curl "
    pkgs+="python3 python3-pip "
    apt_install $pkgs $BH_WSL_APT
    apt_autoremove
    # py
    $HAS_PY && py_set_v3_default
    $HAS_PY && py_install $BH_WSL_PY
    $HAS_PY && py_upgrade
    # cleanup
    home_clean_unused
  }
elif $IS_MSYS; then
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
    log_func
    # update bh
    update_if_needed
    # essentials
    local pkgs="pacman pacman-mirrors msys2-runtime vim diffutils curl $BH_MSYS_PAC"
    pacman_install $pkgs
    pacman --needed -S bash pacman pacman-mirrors msys2-runtime
    pacman -Su --noconfirm
    # py
    $HAS_PY && py_install $BH_MSYS_PY
    $HAS_PY && py_upgrade
    # cleanup
    home_clean_unused
  }
elif $IS_UBU; then
  alias open="xdg-open"
  function ubu_update_clean() {
    log_func
    # update bh
    update_if_needed
    # apt
    local pkgs="git deborphan apt-file vim diffutils curl "
    pkgs+="python3 python3-pip "
    apt_install $pkgs $BH_UBU_APT
    apt_autoremove
    apt_upgrade
    # py
    $HAS_PY && py_set_v3_default
    $HAS_PY && py_install $BH_UBU_PY
    $HAS_PY && py_upgrade
    # vscode
    $HAS_VSCODE && vscode_install $BH_UBU_VSCODE
    # cleanup
    home_clean_unused
  }
elif $IS_MAC; then
  function mac_update_clean() {
    log_func
    # update bh
    update_if_needed
    # brew
    install_mac_brew
    local pkgs="git bash vim diffutils curl "
    pkgs+="python3 python-pip "
    brew_upgrade
    brew_install $pkgs $BH_MAC_BREW
    # py
    $HAS_PY && py_install $BH_MAC_PY
    $HAS_PY && py_upgrade
    # vscode
    brew install --cask visual-studio-code
    $HAS_VSCODE && vscode_install $BH_MAC_VSCODE
    # cleanup
    home_clean_unused
  }
fi

# load $BH_RC or "$HOME/.bhrc.bash"
if test -z $BH_RC ; then 
   BH_RC="$HOME/.bhrc.sh"
fi
if test -f $BH_RC; then 
  source $BH_RC
else
  log_msg "The ~/.bhrc.sh does not exist. You may copy bh/skel/bhrc.sh or define \$BH_RC)."
fi
