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

# ---------------------------------------
# OS helpers
# ---------------------------------------

if $IS_GITBASH; then
  source "$BH_DIR/lib/win.bash"
elif $IS_WSL; then
  source "$BH_DIR/lib/ubu.bash"
  source "$BH_DIR/lib/wsl.bash"
elif $IS_MSYS; then
  source "$BH_DIR/lib/msys.bash"
elif $IS_UBU; then
  source "$BH_DIR/lib/ubu.bash"
elif $IS_MAC; then
  source "$BH_DIR/lib/osx.bash"
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
