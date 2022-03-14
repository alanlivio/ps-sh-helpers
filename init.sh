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
source "$BH_DIR/lib/base.sh" # uses echo, test, md5, curl, tar, unzip, curl, rename, find
if type code &>/dev/null; then HAS_VSCODE=true; source "$BH_DIR/lib/vscode.sh"; else HAS_VSCODE=false; fi
if type python &>/dev/null; then HAS_PY=true;source "$BH_DIR/lib/python.sh"; else HAS_PY=false; fi
if type adb &>/dev/null; then source "$BH_DIR/lib/adb.sh"; fi
if type cmake &>/dev/null; then source "$BH_DIR/lib/cmake.sh"; fi
if type docker &>/dev/null; then source "$BH_DIR/lib/docker.sh"; fi
if type ffmpeg &>/dev/null; then source "$BH_DIR/lib/ffmpeg.sh"; fi
if type flutter &>/dev/null; then source "$BH_DIR/lib/flutter.sh"; fi
if type gcc &>/dev/null; then source "$BH_DIR/lib/gcc.sh"; fi
if type ghostscript &>/dev/null; then source "$BH_DIR/lib/ghostscript.sh"; fi
if type git &>/dev/null; then source "$BH_DIR/lib/git.sh"; fi
if type gst-launch-1.0 &>/dev/null; then source "$BH_DIR/lib/gst.sh"; fi
if type meson &>/dev/null; then source "$BH_DIR/lib/meson.sh"; fi
if type pandoc &>/dev/null; then source "$BH_DIR/lib/pandoc.sh"; fi
if type pngquant &>/dev/null; then source "$BH_DIR/lib/pngquant.sh"; fi
if type pdflatex &>/dev/null; then source "$BH_DIR/lib/pdflatex.sh"; fi
if type pkg-config &>/dev/null; then source "$BH_DIR/lib/pkg-config.sh"; fi
if type ruby &>/dev/null; then source "$BH_DIR/lib/ruby.sh"; fi
if type ssh &>/dev/null; then source "$BH_DIR/lib/ssh.sh"; fi
if type tesseract &>/dev/null; then source "$BH_DIR/lib/tesseract.sh"; fi
if type wget &>/dev/null; then source "$BH_DIR/lib/wget.sh"; fi
if type youtube-dl &>/dev/null; then source "$BH_DIR/lib/youtube-dl.sh"; fi
if type zip &>/dev/null; then source "$BH_DIR/lib/zip.sh"; fi

# ---------------------------------------
# OS helpers
# ---------------------------------------

if $IS_GITBASH; then
  source "$BH_DIR/lib/init-gitbash.sh"
elif $IS_WSL; then
  source "$BH_DIR/lib/init-ubu.sh"
  source "$BH_DIR/lib/init-wsl.sh"
elif $IS_MSYS; then
  source "$BH_DIR/lib/init-msys.sh"
elif $IS_UBU; then
  source "$BH_DIR/lib/init-ubu.sh"
elif $IS_MAC; then
  source "$BH_DIR/lib/init-mac.sh"
fi

# load $BH_RC or "$HOME/.bhrc.sh"
if test -z $BH_RC ; then 
   BH_RC="$HOME/.bhrc.sh"
fi
if test -f $BH_RC; then 
  source $BH_RC
else
  bh_log_msg "The ~/.bhrc.sh does not exist. You may copy bh/skel/bhrc.sh or define \$BH_RC)."
fi
