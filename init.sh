#!/bin/bash

BH_LIB="$(dirname "${BASH_SOURCE[0]}")/lib"
if [ -z "${BH_BIN}" ]; then BH_BIN="$HOME/bin"; fi

#########################
# load os_*.bash files
#########################

source "$BH_LIB/os_any.bash"
case $OSTYPE in
msys*)
  source "$BH_LIB/os_win.bash"
  alias ghostscript='gswin64.exe'
  ;;
linux*)
  source "$BH_LIB/os_linux.bash"
  if [[ -n $WSL_DISTRO_NAME ]]; then source "$BH_LIB/os_win.bash"; fi
  ;;
darwin*)
  source "$BH_LIB/os_mac.bash"
  ;;
esac

#########################
# load <tool>.bash files
#########################

if type adb &>/dev/null; then source "$BH_LIB/adb.bash"; fi
if type cmake &>/dev/null; then source "$BH_LIB/cmake.bash"; fi
if type docker &>/dev/null; then source "$BH_LIB/docker.bash"; fi
if type ffmpeg &>/dev/null; then source "$BH_LIB/ffmpeg.bash"; fi
if type flutter &>/dev/null; then source "$BH_LIB/flutter.bash"; fi
if type ghostscript &>/dev/null; then source "$BH_LIB/ghostscript.bash"; fi
if type git &>/dev/null; then source "$BH_LIB/git.bash"; fi
if type latexmk &>/dev/null; then source "$BH_LIB/latex.bash"; fi
if type lxc &>/dev/null; then source "$BH_LIB/lxc.bash"; fi
if type meson &>/dev/null; then source "$BH_LIB/meson.bash"; fi
if type pandoc &>/dev/null; then source "$BH_LIB/pandoc.bash"; fi
if type python &>/dev/null; then source "$BH_LIB/python.bash"; fi
if type ssh &>/dev/null; then source "$BH_LIB/ssh.bash"; fi
if type wget &>/dev/null; then source "$BH_LIB/wget.bash"; fi
if type youtube-dl &>/dev/null; then source "$BH_LIB/youtube-dl.bash"; fi
if type zip &>/dev/null; then source "$BH_LIB/zip.bash"; fi