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
if type brew &>/dev/null; then source "$BH_DIR/lib/brew.bash"; fi
if type snap &>/dev/null; then
  HAS_SNAP=true
  source "$BH_DIR/lib/snap.bash"
fi

# ---------------------------------------
# OS helpers
# ---------------------------------------

if $IS_GITBASH; then
  source "$BH_DIR/lib/win.bash"
  function bh_setup_win() {
    bh_log_func
    # update bh
    bh_bh_update_if_needed
    # cleanup
    bh_home_clean_unused
    bh_win_explorer_hide_home_dotfiles
    # py
    $HAS_PY && bh_py_install $BH_WIN_PY
    $HAS_PY && bh_py_upgrade
    # vscode
    $HAS_VSCODE && bh_vscode_install $BH_WIN_VSCODE
    # win
    $HAS_GSUDO && bh_win_sysupdate_win
    # winget (it uses --scope=user)
    bh_win_get_install $BH_WIN_GET
  }
elif $IS_WSL; then
  source "$BH_DIR/lib/ubu.bash"
  source "$BH_DIR/lib/wsl.bash"
  function bh_setup_wsl() {
    bh_log_func
    # update bh
    bh_bh_update_if_needed
    # apt
    local pkgs="git deborphan apt-file vim diffutils curl "
    pkgs+="python3 python3-pip "
    bh_ubu_apt_install $pkgs $BH_WSL_APT
    bh_ubu_apt_autoremove
    # py
    $HAS_PY && bh_py_set_v3_default
    $HAS_PY && bh_py_install $BH_WSL_PY
    $HAS_PY && bh_py_upgrade
    # cleanup
    bh_home_clean_unused
  }
elif $IS_MSYS; then
  source "$BH_DIR/lib/msys.bash"
  function bh_setup_msys() {
    bh_log_func
    # update bh
    bh_bh_update_if_needed
    # essentials
    local pkgs="pacman pacman-mirrors msys2-runtime vim diffutils curl $BH_MSYS_PAC"
    bh_msys_install $pkgs
    bh_msys_upgrade
    # py
    $HAS_PY && bh_py_install $BH_MSYS_PY
    $HAS_PY && bh_py_upgrade
    # cleanup
    bh_home_clean_unused
  }
elif $IS_UBU; then
  source "$BH_DIR/lib/ubu.bash"
  alias open="xdg-open"
  function bh_setup_ubu() {
    bh_log_func
    # update bh
    bh_bh_update_if_needed
    # snap
    if $HAS_SNAP; then
      # snap
      bh_snap_install $BH_UBU_SNAP
      bh_snap_upgrade
    fi
    # apt
    local pkgs="git deborphan apt-file vim diffutils curl "
    pkgs+="python3 python3-pip "
    bh_apt_install $pkgs $BH_UBU_APT
    bh_apt_autoremove
    bh_apt_upgrade
    # py
    $HAS_PY && bh_py_set_v3_default
    $HAS_PY && bh_py_install $BH_UBU_PY
    $HAS_PY && bh_py_upgrade
    # vscode
    $HAS_VSCODE && bh_vscode_install $BH_UBU_VSCODE
    # cleanup
    bh_home_clean_unused
  }
elif $IS_MAC; then
  function bh_setup_mac() {
    bh_log_func
    # update bh
    bh_bh_update_if_needed
    # brew
    bh_install_mac_brew
    local pkgs="git bash vim diffutils curl "
    pkgs+="python3 python-pip "
    bh_brew_upgrade
    bh_brew_install $pkgs $BH_MAC_BREW
    # py
    $HAS_PY && bh_py_install $BH_MAC_PY
    $HAS_PY && bh_py_upgrade
    # vscode
    brew install --cask visual-studio-code
    $HAS_VSCODE && bh_vscode_install $BH_MAC_VSCODE
    # cleanup
    bh_home_clean_unused
  }
fi

# load $BH_RC or "$HOME/.bhrc.bash"
if test -z $BH_RC ; then 
   BH_RC="$HOME/.bhrc.sh"
fi
if test -f $BH_RC; then 
  source $BH_RC
else
  bh_log_msg "The ~/.bhrc.sh does not exist. You may copy bh/skel/bhrc.sh or define \$BH_RC)."
fi
