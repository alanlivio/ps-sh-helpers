#!/bin/bash

BH_DIR="$(dirname "${BASH_SOURCE[0]}")"

#########################
# load os_<name>.bash files
#########################

source "$BH_DIR/os_any.bash"
case $OSTYPE in
msys*)
  source "$BH_DIR/os_win.bash"
  alias gs='gswin64.exe'
  alias winpath='cygpath -m'
  ;;
linux*)
  source "$BH_DIR/os_ubu.bash"
  if [[ -n $WSL_DISTRO_NAME ]]; then
    alias winpath='wslpath -m'
    source "$BH_DIR/os_win.bash";
  fi
  ;;
darwin*)
  source "$BH_DIR/os_mac.bash"
  ;;
esac

#########################
# load <command>.bash files
#########################

if type adb &>/dev/null; then source "$BH_DIR/lib/adb.bash"; fi
if type cmake &>/dev/null; then source "$BH_DIR/lib/cmake.bash"; fi
if type docker &>/dev/null; then source "$BH_DIR/lib/docker.bash"; fi
if type ffmpeg &>/dev/null; then source "$BH_DIR/lib/ffmpeg.bash"; fi
if type gs &>/dev/null; then source "$BH_DIR/lib/gs.bash"; fi
if type git &>/dev/null; then source "$BH_DIR/lib/git.bash"; fi
if type lxc &>/dev/null; then source "$BH_DIR/lib/lxc.bash"; fi
if type meson &>/dev/null; then source "$BH_DIR/lib/meson.bash"; fi
if type pandoc &>/dev/null; then source "$BH_DIR/lib/pandoc.bash"; fi
if type python &>/dev/null; then source "$BH_DIR/lib/python.bash"; fi
if type wget &>/dev/null; then source "$BH_DIR/lib/wget.bash"; fi
if type youtube-dl &>/dev/null; then source "$BH_DIR/lib/youtube-dl.bash"; fi