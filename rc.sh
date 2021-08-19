#!/bin/bash

# ---------------------------------------
# OS vars
# ---------------------------------------

IS_MAC=false
IS_LINUX=false
IS_LINUX_UBUNTU=false
IS_WINDOWS=false
IS_WINDOWS_WSL=false
IS_WINDOWS_MSYS=false
IS_WINDOWS_GITBASH=false

case "$(uname -s)" in
CYGWIN* | MINGW* | MSYS*)
  IS_WINDOWS=true
  if type pacman &>/dev/null; then
    IS_WINDOWS_MSYS=true
  else
    IS_WINDOWS_GITBASH=true
  fi
  ;;
Linux)
  if [[ $(uname -r) == *"icrosoft"* ]]; then
    IS_WINDOWS=true
    IS_WINDOWS_WSL=true
  elif [[ $(lsb_release -d | awk '{print $2}') == Ubuntu ]]; then
    IS_LINUX=true
    IS_LINUX_UBUNTU=true
  fi
  ;;
Darwin)
  IS_MAC=true
  ;;
esac

# ---------------------------------------
# bh vars
# ---------------------------------------

BH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BH_RC="$BH_DIR/rc.sh"
BH_SKEL_VSCODE="$BH_DIR/skel/vscode"
BH_PKGS_ESSENTIALS="vim diffutils curl wget "

# ---------------------------------------
# bh vars from .bh-cfg.sh vars
# ---------------------------------------

# if not "$HOME/.bh-cfg.sh" copy skel
if ! test -f "$HOME/.bh-cfg.sh"; then cp $BH_DIR/skel/.bh-cfg.sh $HOME/; fi
source $HOME/.bh-cfg.sh
# set some var if .bh-cfg do not.
if test -z "$BH_OPT_WIN"; then BH_OPT_WIN="$HOME/AppData/Local/Programs"; fi
if test -z "$BH_OPT_LINUX"; then BH_OPT_LINUX="$HOME/opt"; fi
if test -z "$BH_DEV"; then BH_DEV="$HOME/dev"; fi

# ---------------------------------------
# load libs for specific commands
# ---------------------------------------

source "$BH_DIR/lib/curl.sh"
source "$BH_DIR/lib/decompress.sh" # uses tar, unzip, curl
source "$BH_DIR/lib/rename.sh"
source "$BH_DIR/lib/md5.sh"
source "$BH_DIR/lib/log-test.sh"

if type adb &>/dev/null; then source "$BH_DIR/lib/android.sh"; fi
if type arp-scan &>/dev/null; then source "$BH_DIR/lib/arp-scan.sh"; fi
if type cmake &>/dev/null; then source "$BH_DIR/lib/cmake.sh"; fi
if type code &>/dev/null; then source "$BH_DIR/lib/vscode.sh"; fi
if type diff &>/dev/null; then source "$BH_DIR/lib/diff.sh"; fi
if type docker &>/dev/null; then source "$BH_DIR/lib/docker.sh"; fi
if type du &>/dev/null; then source "$BH_DIR/lib/folder-size.sh"; fi
if type ffmpeg &>/dev/null; then source "$BH_DIR/lib/ffmpeg.sh"; fi
if type find &>/dev/null; then source "$BH_DIR/lib/find.sh"; fi
if type flutter &>/dev/null; then source "$BH_DIR/lib/flutter.sh"; fi
if type gcc &>/dev/null; then source "$BH_DIR/lib/gcc.sh"; fi
if type git &>/dev/null; then source "$BH_DIR/lib/git.sh"; fi
if type gst &>/dev/null; then source "$BH_DIR/lib/gst.sh"; fi
if type gst-launch-1.0 &>/dev/null; then source "$BH_DIR/lib/gst.sh"; fi
if type jupyter &>/dev/null; then source "$BH_DIR/lib/jupyter.sh"; fi
if type mount &>/dev/null; then source "$BH_DIR/lib/mount.sh"; fi
if type pandoc &>/dev/null; then source "$BH_DIR/lib/pandoc.sh"; fi
if type pdflatex &>/dev/null; then source "$BH_DIR/lib/pdflatex.sh"; fi
if type pdftk ghostscript &>/dev/null; then source "$BH_DIR/lib/pdf.sh"; fi
if type pkg-config &>/dev/null; then source "$BH_DIR/lib/pkg-config.sh"; fi
if type pngquant jpegoptim &>/dev/null; then source "$BH_DIR/lib/image.sh"; fi
if type pygmentize &>/dev/null; then source "$BH_DIR/lib/pygmentize.sh"; fi
if type python &>/dev/null; then source "$BH_DIR/lib/python.sh"; fi
if type ruby &>/dev/null; then source "$BH_DIR/lib/ruby.sh"; fi
if type ssh &>/dev/null; then source "$BH_DIR/lib/ssh.sh"; fi
if type tesseract &>/dev/null; then source "$BH_DIR/lib/tesseract.sh"; fi
if type wget &>/dev/null; then source "$BH_DIR/lib/wget.sh"; fi
if type youtube-dl &>/dev/null; then source "$BH_DIR/lib/youtube-dl.sh"; fi
if type zip tar &>/dev/null; then source "$BH_DIR/lib/zip.sh"; fi
if test -d /etc/sudoers.d/; then source "$BH_DIR/lib/user.sh"; fi

# ---------------------------------------
# load libs for specific OS
# ---------------------------------------

if $IS_LINUX_UBUNTU; then
  source "$BH_DIR/rc-ubuntu.sh"
elif $IS_WINDOWS_MSYS; then
  source "$BH_DIR/rc-msys.sh"
elif $IS_WINDOWS_WSL; then
  source "$BH_DIR/rc-wsl.sh"
elif $IS_WINDOWS_GITBASH; then
  source "$BH_DIR/rc-gitbash.sh"
elif $IS_MAC; then
  source "$BH_DIR/rc-mac.sh"
fi

# ---------------------------------------
# profile helpers
# ---------------------------------------

function bh_profile_install() {
  bh_log_func
  echo -e "\nsource $BH_RC" >>$HOME/.bashrc
}

function bh_profile_reload() {
  bh_log_func
  if $IS_WINDOWS_WSL; then
    # for WSL
    source $HOME/.profile
  else
    source $HOME/.bashrc
  fi
}

# ---------------------------------------
# home helpers
# ---------------------------------------

function bh_home_config_func() {
  : ${1?"Usage: ${FUNCNAME[0]} backup|install|diff"}
  bh_log_func
  declare -a files_array
  files_array=($BH_CONFIG_BKPS)
  if [ ${#files_array[@]} -eq 0 ]; then
    bh_log_error "BH_CONFIG_BKPS empty"
  fi
  for ((i = 0; i < ${#files_array[@]}; i = i + 2)); do
    bh_test_and_create_file ${files_array[$i]}
    bh_test_and_create_file ${files_array[$((i + 1))]}
    if [ $1 = "backup" ]; then
      cp ${files_array[$i]} ${files_array[$((i + 1))]}
    elif [ $1 = "install" ]; then
      cp ${files_array[$((i + 1))]} ${files_array[$i]}
    elif [ $1 = "diff" ]; then
      ret=$(diff ${files_array[$i]} ${files_array[$((i + 1))]})
      if [ $? = 1 ]; then
        bh_log_msg "diff ${files_array[$i]} ${files_array[$((i + 1))]}"
        echo "$ret"
      fi
    fi
  done
}
alias bh_home_config_install="bh_home_config_func install"
alias bh_home_config_backup="bh_home_config_func backup"
alias bh_home_config_diff="bh_home_config_func diff"

BH_HOME_CLEAN_UNUSED+=(
  'Images'
  'Movies'
  'Public'
  'Templates'
  'Tracing'
  'Videos'
  'Music'
  'Pictures'
)

if $IS_LINUX_UBUNTU; then
  BH_HOME_CLEAN_UNUSED+=(
    'Documents' # sensible data in Windows
  )
elif $IS_WINDOWS; then
  BH_HOME_CLEAN_UNUSED+=(
    'Application Data'
    'Cookies'
    'OpenVPN'
    'Local Settings'
    'Start Menu'
    '3D Objects'
    'Contacts'
    'Favorites'
    'Intel'
    'IntelGraphicsProfiles'
    'Links'
    'MicrosoftEdgeBackups'
    'My Documents' # symlink
    'NetHood'
    'PrintHood'
    'Recent'
    'Saved Games'
    'Searches'
    'SendTo'
  )
fi

function bh_home_clean_unused() {
  bh_log_func
  for i in "${BH_HOME_CLEAN_UNUSED[@]}"; do
    if test -d "$HOME/$i"; then
      if $IS_MAC; then
        sudo rm -rf "$HOME/${i:?}" >/dev/null
      else
        rm -rf "$HOME/${i:?}" >/dev/null
      fi
    elif test -f "$HOME/$i"; then
      echo remove $i
      if $IS_MAC; then
        sudo rm -f "$HOME/$i" >/dev/null
      else
        rm -f "$HOME/${i:?}" >/dev/null
      fi
    fi
  done
}
