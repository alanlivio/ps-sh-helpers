#!/bin/bash

function log_error() { echo -e "\033[00;31m-- $* \033[00m"; }
function log_msg() { echo -e "\033[00;33m-- $* \033[00m"; }
function test_and_create_dir() { if ! test -d "$1"; then mkdir -p $1; fi; }
alias bashrc_reload='source $HOME/.bashrc'
BH_DIR="$(dirname "${BASH_SOURCE[0]}")"

# ---------------------------------------
# os
# ---------------------------------------
case $OSTYPE in
msys*)
  # if msys
  if ! test -e /etc/profile.d/git-prompt.sh; then 
    source "$BH_DIR/lib/msys.bash"
  else # if gitbash
    BH_OPT="$HOME/AppData/Local/Programs"
    source "$BH_DIR/lib/win.bash"
    alias ghostscript='gswin64c'
  fi
  ;;
linux*)
  BH_OPT="$HOME/opt"
  if type gnome-shell &>/dev/null; then source "$BH_DIR/lib/gnome.bash"; fi
  BH_HOME_CLEAN_UNUSED+=('Documents') # sensible data in Windows
  ;;
esac

# ---------------------------------------
# aliases command
# ---------------------------------------
if type adb &>/dev/null; then source "$BH_DIR/lib/commands/adb.bash"; fi
if type apt &>/dev/null; then source "$BH_DIR/lib/commands/apt.bash"; fi
if type deb &>/dev/null; then source "$BH_DIR/lib/commands/deb.bash"; fi
if type flutter &>/dev/null; then source "$BH_DIR/lib/commands/flutter.bash"; fi
if type pngquant &>/dev/null; then source "$BH_DIR/lib/commands/pngquant.bash"; fi
if type python &>/dev/null; then source "$BH_DIR/lib/commands/python.bash"; fi
if type ruby &>/dev/null; then source "$BH_DIR/lib/commands/ruby.bash"; fi
if type snap &>/dev/null; then source "$BH_DIR/lib/commands/snap.bash"; fi
if type code &>/dev/null; then source "$BH_DIR/lib/commands/vscode.bash"; fi
if type choco &>/dev/null; then source "$BH_DIR/lib/commands/choco.bash"; fi
if type cmake &>/dev/null; then source "$BH_DIR/lib/commands/cmake.bash"; fi
if type ffmpeg &>/dev/null; then source "$BH_DIR/lib/commands/ffmpeg.bash"; fi
if type ghostscript &>/dev/null; then source "$BH_DIR/lib/commands/ghostscript.bash"; fi
if type git &>/dev/null; then source "$BH_DIR/lib/commands/git.bash"; fi
if type gst-launch-1.0 &>/dev/null; then source "$BH_DIR/lib/commands/gst.bash"; fi
if type lxc &>/dev/null; then source "$BH_DIR/lib/commands/lxc.bash"; fi
if type meson &>/dev/null; then source "$BH_DIR/lib/commands/meson.bash"; fi
if type pandoc &>/dev/null; then source "$BH_DIR/lib/commands/pandoc.bash"; fi
if type pkg-config &>/dev/null; then source "$BH_DIR/lib/commands/pkg-config.bash"; fi
if type ssh &>/dev/null; then source "$BH_DIR/lib/commands/ssh.bash"; fi
if type tesseract &>/dev/null; then source "$BH_DIR/lib/commands/tesseract.bash"; fi
if type youtube-dl &>/dev/null; then source "$BH_DIR/lib/commands/youtube-dl.bash"; fi


# ---------------------------------------
# dotfiles
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

# ---------------------------------------
# others
# ---------------------------------------

function decompress() {
  : ${1?"Usage: ${FUNCNAME[0]} <zip-name> [dir-name]"}
  local EXT=${1##*.}
  local DST
  if [ $# -eq 1 ]; then DST=.; else DST=$2; fi
  case $EXT in
  tgz)
    tar -xzf $1 -C $DST
    ;;
  gz) # consider tar.gz
    tar -xf $1 -C $DST
    ;;
  bz2) # consider tar.bz2
    tar -xjf $1 -C $DST
    ;;
  zip)
    unzip $1 -d $DST
    ;;
  zst)
    tar --use-compress-program=unzstd -xvf $1 -C $DST
    ;;
  xz)
    tar -xJf $1 -C $DST
    ;;
  *)
    log_error "$EXT is not supported compress." && return
    ;;
  esac
}

function decompress_from_url() {
  : ${2?"Usage: ${FUNCNAME[0]} <URL> <dir>"}
  local file_name="/tmp/$(basename $1)"

  if test ! -f $file_name; then
    curl -O $1 --create-dirs --output-dir /tmp/
  fi
  echo "extracting $file_name to $2"
  decompress $file_name $2
}

function bash_sudo_nopasswd() {
  if ! test -d /etc/sudoers.d/; then test_and_create_dir /etc/sudoers.d/; fi
  SET_USER=$USER && sudo sh -c "echo $SET_USER 'ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sudoers-user"
}

function dir_sorted_by_size() {
  du -ahd 1 | sort -h
}

function dir_find_duplicated_pdf() {
  find . -iname "*.pdf" -not -empty -type f -printf "%s\n" | sort -rn | uniq -d | xargs -I{} -n1 find . -type f -size {}c -print0 | xargs -r -0 md5sum | sort | uniq -w32 --all-repeated=separate
}

# ---------------------------------------
# update_clean_os
# ---------------------------------------

function home_clean_unused() {
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
}

function update_clean_os() {
  home_clean_unused # clean for any OS
  case $OSTYPE in
  linux*) # wsl/ubu
    local pkgs="git vim diffutils curl python3 python3-pip "
    if [[ $(uname -r) == *"icrosoft"* ]]; then
        apt_install $pkgs $BH_WSL_APT
        python_install $BH_WSL_PY
    elif [[ $(lsb_release -d | awk '{print $2}') == Ubuntu ]]; then
      apt_install $pkgs $BH_UBU_APT
      python_install $BH_UBU_PY
    fi
    ;;

  msys*) # gitbas/msys
    win_hide_home_dotfiles
    if [ $(win_is_user_admin) = "True" ]; then win_get_install "gerardog.gsudo"; fi
    if type gsudo &>/dev/null; then win_sys_update; fi
    if test -e /etc/profile.d/git-prompt.sh; then # if gitbash
      local pkgs+="Python.Python.3 " # ensure python installed
      win_get_install $pkgs $BH_WIN_GET  # winget (it uses --scope=user)
      python_install $BH_WIN_PY
    else  # if msys
      local pkgs="bash pacman pacman-mirrors msys2-runtime vim diffutils curl "
      msys_install $pkgs $BH_MSYS_PAC
      python_install $BH_MSYS_PY
    fi
    python_upgrade
    ;;

  darwin*) # mac
      local pkgs="git bash vim diffutils curl "
      pkgs+="python3 python-pip " # ensure python installed
      brew install $pkgs $BH_MAC_BREW
      python_install $BH_MAC_PY
    ;;
  esac
}
