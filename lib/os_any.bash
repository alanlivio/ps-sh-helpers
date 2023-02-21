#########################
# log
#########################

function log_error() { echo -e "\033[00;31m-- $* \033[00m"; }
function log_msg() { echo -e "\033[00;33m-- $* \033[00m"; }
function log_msg() { echo -e "\033[00;33m-- $* \033[00m"; }
function log_run() { log_msg "$*" && eval "$*"; }

function test_and_create_dir() { if ! test -d "$1"; then mkdir -p $1; fi; }
alias return_if_last_command_fail='if [ $? != 0 ]; then log_error ${FUNCNAME[0]} fail; return 1; fi'

#########################
# bashrc
#########################
alias bashrc_reload='source $HOME/.bashrc'

function bashrc_setup_prompt() {
  echo 'export PS1="\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\] \n$ "' >>$HOME/.bashrc
}

#########################
# home
#########################

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

#########################
# dotfiles
#########################

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
  if [[ $OSTYPE == "msys"* ]]; then
    explorer_hide_home_dotfiles
    if [ -n "$BH_HOME_UNUSED_WIN_HIDE" ]; then
      local list=$(printf '"%s"' "${BH_HOME_UNUSED_WIN_HIDE[@]}" | sed 's/""/","/g')
      powershell -c '
        $list =' "$list" '
        $nodes = Get-ChildItem ${env:userprofile} | Where-Object {$_.name -In $list}
        $nodes | ForEach-Object { $_.Attributes += "Hidden" }
      '
    fi
  fi
}

#########################
# pkgs_install
#########################

function pkgs_install() {
  case $OSTYPE in
  linux*)
    if [[ $(uname -r) == *"WSL"* ]]; then # wsl
      log_msg "apt_install BH_WSL_APT=$BH_WSL_APT"
      apt_install $min_pkgs $BH_WSL_APT
      log_msg "pip_install BH_WSL_PIP=$BH_WSL_PIP"
      pip_install $BH_WSL_PIP
    elif [[ $(lsb_release -d | awk '{print $2}') == Ubuntu ]]; then #ubu
      log_msg "apt_install BH_UBU_APT=$BH_UBU_APT"
      apt_install $min_pkgs $BH_UBU_APT
      log_msg "pip_install BH_WIN_PIP=$BH_WIN_PIP"
      pip_install $BH_UBU_PIP
    fi
    ;;
  msys*)
    if test -e /etc/profile.d/git-prompt.sh; then # gitbash
      log_msg "winget_install BH_WIN_GET=$BH_WIN_GET"
      winget_install $BH_WIN_GET
      log_msg "pip_install BH_WIN_PIP=$BH_WIN_PIP"
      pip_install $BH_WIN_PIP
    else # msys
      log_msg "msys2_install BH_MSYS_PAC=$BH_MSYS_PAC"
      msys2_install $BH_MSYS_PAC
      log_msg "pip_install BH_MSYS_PIP=$BH_MSYS_PIP"
      pip_install $BH_MSYS_PIP
    fi
    ;;
  darwin*) # mac
    log_msg "brew_install BH_MAC_BREW=$BH_MAC_BREW"
    brew install $BH_MAC_BREW
    log_msg "pip_install BH_MAC_PIP=$BH_MAC_PIP"
    pip_install $BH_MAC_PIP
    ;;
  esac
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

function pdf_info() {
  : ${1?"Usage: ${FUNCNAME[0]} <pdf file>"}
  pdfinfo $1
}

function folder_count_files() {
  find . -maxdepth 1 -type f | wc -l
}

function folder_count_files_recusive() {
  find . -maxdepth 1 -type f | wc -l
}

function folder_list_sorted_by_size() {
  du -ahd 1 | sort -h
}

function folder_find_duplicated_pdf() {
  find . -iname "*.pdf" -not -empty -type f -printf "%s\n" | sort -rn | uniq -d | xargs -I{} -n1 find . -type f -size {}c -print0 | xargs -r -0 md5sum | sort | uniq -w32 --all-repeated=separate
}

function user_sudo_nopasswd() {
  if ! test -d /etc/sudoers.d/; then test_and_create_dir /etc/sudoers.d/; fi
  SET_USER=$USER && sudo sh -c "echo $SET_USER 'ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sudoers-user"
}
