#########################
# basic
#########################

function log_error() { echo -e "\033[00;31m-- $* \033[00m"; }
function log_msg() { echo -e "\033[00;33m-- $* \033[00m"; }
function log_msg() { echo -e "\033[00;33m-- $* \033[00m"; }
function log_run() { log_msg "$*" && eval "$*"; }
function test_and_create_dir() { if ! test -d "$1"; then mkdir -p $1; fi; }
alias return_if_last_command_fail='if [ $? != 0 ]; then log_error ${FUNCNAME[0]} fail; return 1; fi'
alias bashrc_reload='source $HOME/.bashrc'
alias folder_count_files='find . -maxdepth 1 -type f | wc -l'
alias folder_count_files_recusive='find . -maxdepth 1 -type f | wc -l'
alias folder_list_sorted_by_size='du -ahd 1 | sort -h'

#########################
# dotfiles
#########################

function dotfiles_func() {
  : ${1?"Usage: ${FUNCNAME[0]} backup|install|diff"}
  declare -a files_array
  files_array=($BH_DOTFILES)
  if [ ${#files_array[@]} -eq 0 ]; then log_error "BH_DOTFILES empty" && return 1; fi
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
  if [ -n "$BH_HOME_UNUSED_CLEAN" ]; then
    for i in "${BH_HOME_UNUSED_CLEAN[@]}"; do
      if test -d "$HOME/$i"; then
        rm -rf "$HOME/${i:?}" >/dev/null
      elif test -e "$HOME/$i"; then
        rm -f "$HOME/${i:?}" >/dev/null
      fi
    done
  fi
}

#########################
# pkgs_install
#########################

function pkgs_install() {
  if type apt &>/dev/null && [ -n "$BH_PKGS_APT" ]; then
    apt_install $BH_PKGS_APT
  fi
  if type winget &>/dev/null && [ -n "$BH_PKGS_WINGET" ]; then
    winget_install $BH_PKGS_WINGET
  fi
  if type pacman &>/dev/null && [ -n "$BH_PKGS_MSYS2" ]; then
    msys2_install $BH_PKGS_MSYS2
  fi
  if type brew &>/dev/null && [ -n "$BH_PKGS_MAC_BREW" ]; then
    brew install $BH_PKGS_MAC_BREW
  fi
}

#########################
# arp
#########################

function arp_list() {
  if [[ $OSTYPE == "msys"* ]]; then
    arp //a
  else
    arp -a
  fi
}

#########################
# decompress/folder/user
#########################

function decompress() {
  : ${1?"Usage: ${FUNCNAME[0]} <zip-name> [dir-name]"}
  local filename=$(basename $1)
  local filename_noext="${filename%.*}"
  local dest
  if [ $# -eq 1 ]; then dest=.; else dest=$2; fi
  case $filename in
  *.tar.bz2 | *.tbz | *.tbz2) ret=$(tar -xzf $1 -C $dest) ;;
  *.gz | *.Z) ret=$(gunzip $1 >$dest/$filename_noext) ;;
  *bz2) ret=$(tar -xjf $1 -C $dest) ;;
  *.zip) ret=$(unzip $1 -d $dest) ;;
  *.zst) ret=$(tar --use-compress-program=unzstd -xvf $1 -C $dest) ;;
  *.xz) ret=$(tar -xJf $1 -C $dest) ;;
  *) log_error "$EXT is not supported compress." && return 1 ;;
  esac
  if [ $? != 0 ] || ! [ -f $file_name ]; then
    log_error "decompress $1 failed " && return 1
  fi
}

function decompress_from_url() {
  : ${2?"Usage: ${FUNCNAME[0]} <URL> <dir>"}
  local file_name="/tmp/$(basename $1)"
  if test ! -s $file_name; then
    log_msg "fetching $1 to /tmp/"
    curl -LJ $1 --create-dirs --output $file_name
    return_if_last_command_fail
  fi
  log_msg "extracting $file_name to $2"
  decompress $file_name $2
}

function decompress_from_url_one_file_and_move_to_bin() {
  : ${2?"Usage: ${FUNCNAME[0]} <URL> <bin_file_to_be_installed>]"}
  decompress_from_url $1 /tmp/
  return_if_last_command_fail
  local dir_name="/tmp/$(basename $1)" # XXX.zip
  dir_name="${dir_name%.*}"            # XXX
  log_msg "coping $dir_name/$2 to $BH_BIN"
  cp $dir_name/$2 $BH_BIN
}

#########################
# ssh
#########################

function ssh_fix_permissions() {
  chmod 700 $HOME/.ssh/
  if test -e $HOME/.ssh/id_rsa; then
    chmod 600 $HOME/.ssh/id_rsa
    chmod 640 $HOME/.ssh/id_rsa.pubssh-rsa
  fi
}

function ssh_send_to_server_authorized_pub_key() {
  : ${1?"Usage: ${FUNCNAME[0]} <user@server>"}
  ssh "$1" sh -c 'cat - >> ~/.ssh/authorized_keys' <$HOME/.ssh/id_rsa.pub
}

function ssh_send_to_server_priv_key() {
  : ${1?"Usage: ${FUNCNAME[0]} <user@server>"}
  ssh "$1" sh -c 'cat - > ~/.ssh/id_rsa;chmod 600 $HOME/.ssh/id_rsa' <$HOME/.ssh/id_rsa
}

#########################
# clean
#########################

function latex_clean() {
  rm -rf _markdown* *.markdown.lua *.aux *.dvi *.log *.lox *.out *.lol *.pdf *.synctex.gz _minted-* *.bbl *.blg *.lot *.lof *.toc *.lol *.fdb_latexmk *.fls *.bcf
}
