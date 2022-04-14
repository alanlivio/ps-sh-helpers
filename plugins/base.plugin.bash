# ---------------------------------------
# log
# ---------------------------------------

alias log_func='log_msg "${FUNCNAME[0]}"'
alias log_not_implemented_return="log_error 'Not implemented'; return;"

function log_wrap() {
  echo -e "$1" | fold -w100 -s
}

function log_error() {
  log_wrap "\033[00;31m-- $* \033[00m"
}

function log_msg() {
  log_wrap "\033[00;33m-- $* \033[00m"
}

function log_msg_2nd() {
  log_wrap "\033[00;33m-- > $* \033[00m"
}

function log_done() {
  log_wrap "\033[00;32m-- done\033[00m"
}

function log_ok() {
  log_wrap "\033[00;32m-- ok\033[00m"
}

function log_try() {
  "$@"
  if [ $? -ne 0 ]; then log_error "$1" && exit 1; fi
}

# ---------------------------------------
# bashrc helpers
# ---------------------------------------

function bashrc_reload() {
  log_func
  source $HOME/.bashrc
}

# ---------------------------------------
# bh helpers
# ---------------------------------------

function update_if_needed() {
  cd $BH_DIR
  if $(git_check_if_need_pull); then
    log_func
    git pull
    bashrc_reload
  fi
  cd $OLDPWD
}

# ---------------------------------------
# test
# ---------------------------------------

function test_and_create_dir() {
  if test ! -d $1; then
    log_msg "creating $1"
    mkdir -p $1
  fi
}

function test_and_create_file() {
  : ${1?"Usage: ${FUNCNAME[0]} [file]"}
  if ! test -f "$1"; then
    test_and_create_dir $(dirname $1)
    touch "$1"
  fi
}

function test_and_delete_dir() {
  if test -d $1; then rm -rf $1; fi
}

# ---------------------------------------
# md5
# ---------------------------------------

function md5_compare_files() {
  : ${2?"Usage: ${FUNCNAME[0]} [file1] [file2]"}
  if [ $(md5sum $1 | awk '{print $1;exit}') == $(md5sum $2 | awk '{print $1;exit}') ]; then echo "same"; else echo "different"; fi
}

# ---------------------------------------
# curl
# ---------------------------------------

function curl_get() {
  curl -i -s -X GET $1
}

function curl_post() {
  curl -i -s -X POST $1
}

function curl_post_json() {
  curl -i -s -X POST $1 --header 'Content-Type: application/json' --header 'Accept: application/json' -d "$2"
}

function curl_fetch_to_dir() {
  curl -O $1 --create-dirs --output-dir $2
}

# ---------------------------------------
# decompress
# ---------------------------------------

function decompress_zip() {
  : ${1?"Usage: ${FUNCNAME[0]} <zip-name>"}
  unzip $1 -d "${1%%.zip}"
}

function decompress_zip_list() {
  : ${1?"Usage: ${FUNCNAME[0]} <zip-name>"}
  unzip -l $1
}

function decompress() {
  : ${1?"Usage: ${FUNCNAME[0]} <zip-name> [dir-name]"}
  local EXT=${1##*.}
  local DST
  if [ $# -eq 1 ]; then
    DST=.
  else
    DST=$2
  fi

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
    log_error "$EXT is not supported compress." && exit
    ;;
  esac
}

function decompress_from_url() {
  : ${2?"Usage: ${FUNCNAME[0]} <URL> <dir>"}
  local file_name="/tmp/$(basename $1)"

  if test ! -f $file_name; then
    curl_fetch_to_dir $1 /tmp/
  fi
  echo "extracting $file_name to $2"
  decompress $file_name $2
}

# ---------------------------------------
# diff
# ---------------------------------------

function diff() {
  : ${2?"Usage: ${FUNCNAME[0]} <old_file> <new_file>"}
  diff "$1" "$2"
}

function diff_apply() {
  : ${2?"Usage: ${FUNCNAME[0]} <patch> <targed_file>"}
  patch apply "$1" "$2"
}

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
    test_and_create_file ${files_array[$i]}
    test_and_create_file ${files_array[$((i + 1))]}
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
# home
# ---------------------------------------

function home_clean_unused() {
  log_func
  for i in "${BH_HOME_CLEAN_UNUSED[@]}"; do
    if test -d "$HOME/$i"; then
      if $IS_MAC; then
        sudo rm -rf "$HOME/${i:?}" >/dev/null
      else
        rm -rf "$HOME/${i:?}" >/dev/null
      fi
    elif test -e "$HOME/$i"; then
      echo remove $i
      if $IS_MAC; then
        sudo rm -f "$HOME/$i" >/dev/null
      else
        rm -f "$HOME/${i:?}" >/dev/null
      fi
    fi
  done
}

function dev_dir_git_repos() {
  log_func

  # create dev dir
  test_and_create_dir $BH_DEV
  local cwd=$(pwd)

  declare -a repos_array
  repos_array=($BH_DEV_REPOS)
  for ((i = 0; i < ${#repos_array[@]}; i = i + 2)); do
    local parent=$BH_DEV/${repos_array[$i]}
    local repo=${repos_array[$((i + 1))]}
    # create parent
    if ! test -d $parent; then
      test_and_create_dir $parent
    fi
    # clone/pull repo
    local repo_basename="$(basename -s .git $repo)"
    local dst_dir="$parent/$repo_basename"
    if ! test -d "$dst_dir"; then
      log_msg_2nd "clone $dst_dir"
      cd $parent
      git clone $repo
    else
      cd $dst_dir
      log_msg_2nd "pull $dst_dir"
      git pull
    fi
  done
  cd $cwd
}

# ---------------------------------------
# rename
# ---------------------------------------

function rename_to_prefix() {
  : ${2?"Usage: ${FUNCNAME[0]} <prefix> <files..>"}
  echo $@
  local prefix="$1"
  shift
  for i in "$@"; do mv $i $prefix$i; done
}

function rename_to_lowercase_with_underscore() {
  : ${1?"Usage: ${FUNCNAME[0]} <file_name>"}
  echo "rename to lowercase with underscore"
  rename 'y/A-Z/a-z/' "$@"
  echo "replace '.', ' ', and '-' by '_''"
  rename 's/-+/_/g;s/\.+/_/g;s/ +/_/g' "$@"
}

function rename_to_lowercase_with_dash() {
  : ${1?"Usage: ${FUNCNAME[0]} <file_name>"}
  echo "rename to lowercase with dash"
  rename 'y/A-Z/a-z/' "$@"
  echo "replace '.', ' ', and '-' by '_''"
  rename 's/_+/-/g;s/\.+/-/g;s/ +/-/g' "$@"
}

# ---------------------------------------
# user
# ---------------------------------------

function user_sudo_nopasswd() {
  if ! test -d /etc/sudoers.d/; then test_and_create_dir /etc/sudoers.d/; fi
  SET_USER=$USER && sudo sh -c "echo $SET_USER 'ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sudoers-user"
}

function user_passwd_disable_len_restriction() {
  sudo sed -i 's/sha512/minlen=1 sha512/g' /etc/pam.d/common-password
}

function user_permissions_opt() {
  log_func
  sudo chown -R root:root /opt
  sudo chmod -R 775 /opt/
  grep root /etc/group | grep $USER >/dev/null
  newgrp root
}

function user_lang_set_en() {
  local line='export LANG="en_US.UTF-8"'
  if ! grep -Fxq "$line" $HOME/.bashrc; then
    echo -e 'export LANG="en_US.UTF-8"' >>$HOME/.bashrc
    echo -e 'export LC_ALL="en_US.UTF-8"' >>$HOME/.bashrc
  fi
}

# ---------------------------------------
# dir
# ---------------------------------------

function dir_sorted_by_size() {
  du -ahd 1 | sort -h
}

function dir_info() {
  local extensions=$(for f in *.*; do printf "%s\n" "${f##*.}"; done | sort -u)
  echo "size="$(du -sh | awk '{print $1;exit}')
  echo "dirs="$(find . -mindepth 1 -maxdepth 1 -type d | wc -l)
  echo -n "files="$(find . -mindepth 1 -maxdepth 1 -type f | wc -l)"("
  for i in $extensions; do
    echo -n ".$i="$(find . -mindepth 1 -maxdepth 1 -type f -iname \*\.$i | wc -l)","
  done
  echo ")"
}

function dir_find_duplicated_pdf() {
  find . -iname "*.pdf" -not -empty -type f -printf "%s\n" | sort -rn | uniq -d | xargs -I{} -n1 find . -type f -size {}c -print0 | xargs -r -0 md5sum | sort | uniq -w32 --all-repeated=separate
}

# ---------------------------------------
# mount
# ---------------------------------------

function mount_list() {
  df -haT
}

# ---------------------------------------
# hub
# ---------------------------------------

hub_latest_release_url() {
  : ${2?"Usage: ${FUNCNAME[0]} <user-with-slash/repo> <installer_extension>"}
  # ref: curl -s https://api.github.com/repos/microsoft/winget-cli/releases/latest| grep -E 'browser_download_url' | grep -E 'msixbundle'  | cut -d '"' -f 4
  curl -s https://api.github.com/repos/$1/releases/latest | grep -E 'browser_download_url' | grep -E $2 | cut -d '"' -f 4
}
