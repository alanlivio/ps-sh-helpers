#!/bin/bash

function log_error() { echo -e "\033[00;31m-- $* \033[00m"; }
function log_msg() { echo -e "\033[00;33m-- $* \033[00m"; }
function test_and_create_dir() { if ! test -d "$1"; then mkdir -p $1; fi; }
alias bashrc_reload='source $HOME/.bashrc'
BH_DIR="$(dirname "${BASH_SOURCE[0]}")"
if [ -z "${BH_BIN}" ]; then BH_BIN="$HOME/bin"; fi

# ---------------------------------------
# load .bash files
# ---------------------------------------
case $OSTYPE in
msys*)
  source "$BH_DIR/win.bash"
  alias ghostscript='gswin64.exe'
  ;;
linux*)
  source "$BH_DIR/ubu.bash"
  if [[ -n $WSL_DISTRO_NAME ]]; then source "$BH_DIR/win.bash"; fi
  ;;
darwin*)
  source "$BH_DIR/mac.bash"
  ;;
esac

if type adb &>/dev/null; then source "$BH_DIR/lib/adb.bash"; fi
if type cmake &>/dev/null; then source "$BH_DIR/lib/cmake.bash"; fi
if type code &>/dev/null; then source "$BH_DIR/lib/code.bash"; fi
if type ffmpeg &>/dev/null; then source "$BH_DIR/lib/ffmpeg.bash"; fi
if type flutter &>/dev/null; then source "$BH_DIR/lib/flutter.bash"; fi
if type ghostscript &>/dev/null; then source "$BH_DIR/lib/ghostscript.bash"; fi
if type git &>/dev/null; then source "$BH_DIR/lib/git.bash"; fi
if type gst-launch-1.0 &>/dev/null; then source "$BH_DIR/lib/gst.bash"; fi
if type latexmk &>/dev/null; then source "$BH_DIR/lib/latex.bash"; fi
if type lxc &>/dev/null; then source "$BH_DIR/lib/lxc.bash"; fi
if type meson &>/dev/null; then source "$BH_DIR/lib/meson.bash"; fi
if type pandoc &>/dev/null; then source "$BH_DIR/lib/pandoc.bash"; fi
if type pkg-config &>/dev/null; then source "$BH_DIR/lib/pkg-config.bash"; fi
if type pngquant &>/dev/null; then source "$BH_DIR/lib/pngquant.bash"; fi
if type python &>/dev/null; then source "$BH_DIR/lib/python.bash"; fi
if type ruby &>/dev/null; then source "$BH_DIR/lib/ruby.bash"; fi
if type ssh &>/dev/null; then source "$BH_DIR/lib/ssh.bash"; fi
if type tesseract &>/dev/null; then source "$BH_DIR/lib/tesseract.bash"; fi
if type wget &>/dev/null; then source "$BH_DIR/lib/wget.bash"; fi
if type youtube-dl &>/dev/null; then source "$BH_DIR/lib/youtube-dl.bash"; fi
if type zip &>/dev/null; then source "$BH_DIR/lib/zip.bash"; fi

# ---------------------------------------
# home/dotfiles/pkgs helpers
# ---------------------------------------

function dotfiles_func() {
  : ${1?"Usage: ${FUNCNAME[0]} backup|install|diff"}
  declare -a files_array
  files_array=($BH_DOTFILES)
  if [ ${#files_array[@]} -eq 0 ]; then
    log_error "BH_DOTFILES empty"
  fi
  for ((i = 0; i < ${#files_array[@]}; i = i + 2)); do
    if [ $1 = "backup" ]; then
      cp ${files_array[$i]} ${files_array[$((i + 1))]}
    elif [ $1 = "install" ]; then
      cp ${files_array[$((i + 1))]} ${files_array[$i]}
    elif [ $1 = "diff" ]; then
      ret=$(diff ${files_array[$i]} ${files_array[$((i + 1))]})
      if [ $? = 1 ]; then
        log_msg "diff ${files_array[$i]} ${files_array[$((i + 1))]}"
        echo "$ret"
      fi
    fi
  done
}
alias dotfiles_install="dotfiles_func install"
alias dotfiles_backup="dotfiles_func backup"
alias dotfiles_diff="dotfiles_func diff"

function home_cleanup() {
  if [ -z $BH_HOME_CLEAN_UNUSED ]; then
    log_error "\$BH_HOME_CLEAN_UNUSED is not defined"
    return
  fi
    for i in "${BH_HOME_CLEAN_UNUSED[@]}"; do
      if test -d "$HOME/$i"; then
        rm -rf "$HOME/${i:?}" >/dev/null
    elif test -e "$HOME/$i"; then
        rm -f "$HOME/${i:?}" >/dev/null
    fi
  done
  case $OSTYPE in
  msys*) # gitbas/msys
    win_hide_home_dotfiles ;;
  esac
}

function pkgs_install() {
  case $OSTYPE in
  linux*)
    local pkgs="git vim diffutils curl python3 python3-pip "
    if [[ $(uname -r) == *"WSL"* ]]; then # wsl
      log_msg "install BH_WSL_APT=$BH_WSL_APT"
      apt_install $pkgs $BH_WSL_APT
      log_msg "install BH_WSL_PY=$BH_WSL_PY"
      python_install $BH_WSL_PY
    elif [[ $(lsb_release -d | awk '{print $2}') == Ubuntu ]]; then #ubu
      log_msg "install BH_UB pkgs"
      apt_install $pkgs $BH_UBU_APT
      python_install $BH_UBU_PY
    fi
    ;;
  msys*)
    if test -e /etc/profile.d/git-prompt.sh; then # gitbash
      log_msg "install BH_WIN_GET=$BH_WIN_GET"
      win_get_install $pkgs $BH_WIN_GET  # winget (it uses --scope=user)
      log_msg "install BH_WIN_PY=$BH_WIN_PY"
      python_install $BH_WIN_PY
    else  # msys
      log_msg "install BH_MSYS pkgs"
      local pkgs="bash pacman pacman-mirrors msys2-runtime vim diffutils curl "
      log_msg "install BH_MSYS_PAC=$BH_MSYS_PAC"
      msys_install $pkgs $BH_MSYS_PAC
      log_msg "install BH_MSYS_PY=$BH_MSYS_PY"
      python_install $BH_MSYS_PY
    fi
    ;;
  darwin*) # mac
      log_msg "install BH_MAC pkgs"
      local pkgs="git bash vim diffutils curl "
      log_msg "install BH_MAC_BREW=$BH_MAC_BREW"
      brew install $pkgs $BH_MAC_BREW
      log_msg "install BH_MAC_PY=$BH_MAC_PY"
      python_install $BH_MAC_PY
    ;;
  esac
}

# ---------------------------------------
# decompress/dir/use commands
# ---------------------------------------

function decompress() {
  : ${1?"Usage: ${FUNCNAME[0]} <zip-name> [dir-name]"}
  local EXT=${1##*.}
  local DST
  if [ $# -eq 1 ]; then DST=.; else DST=$2; fi
  case $EXT in
  tgz)
    ret=$(tar -xzf $1 -C $DST)
    ;;
  gz)
    ret=$(tar -xf $1 -C $DST)
    ;;
  bz2)
    ret=$(tar -xjf $1 -C $DST)
    ;;
  zip)
    ret=$(unzip $1 -d $DST)
    ;;
  zst)
    ret=$(tar --use-compress-program=unzstd -xvf $1 -C $DST)
    ;;
  xz)
    ret=$(tar -xJf $1 -C $DST)
    ;;
  *)
    log_error "$EXT is not supported compress." && return
    return
    ;;
  esac
  if [ $? != 0 ] || ! [ -f $file_name ]; then
    log_error "decompress $1 failed "
    return
  fi
}

function decompress_from_url() {
  : ${2?"Usage: ${FUNCNAME[0]} <URL> <dir>"}
  local file_name="/tmp/$(basename $1)"
  if test ! -f $file_name; then
    curl -O $1 --create-dirs --output-dir /tmp/
  fi
  if [ $? != 0 ] || ! [ -f $file_name ]; then
    log_error "fetching $1 failed "
    return
  fi
  log_msg "extracting $(basename $1) to $2"
  decompress $file_name $2
}

function user_sudo_nopasswd() {
  if ! test -d /etc/sudoers.d/; then test_and_create_dir /etc/sudoers.d/; fi
  SET_USER=$USER && sudo sh -c "echo $SET_USER 'ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sudoers-user"
}

function dir_sorted_by_size() {
  du -ahd 1 | sort -h
}

function dir_find_duplicated_pdf() {
  find . -iname "*.pdf" -not -empty -type f -printf "%s\n" | sort -rn | uniq -d | xargs -I{} -n1 find . -type f -size {}c -print0 | xargs -r -0 md5sum | sort | uniq -w32 --all-repeated=separate
}
