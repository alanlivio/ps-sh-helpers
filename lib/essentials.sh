# ---------------------------------------
# log
# ---------------------------------------

alias bh_log_func='bh_log_msg "${FUNCNAME[0]}"'
alias bh_log_not_implemented_return="bh_log_error 'Not implemented'; return;"

function bh_log_wrap() {
  echo -e "$1" | fold -w100 -s
}

function bh_log_error() {
  bh_log_wrap "\033[00;31m-- $* \033[00m"
}

function bh_log_msg() {
  bh_log_wrap "\033[00;33m-- $* \033[00m"
}

function bh_log_msg_2nd() {
  bh_log_wrap "\033[00;33m-- > $* \033[00m"
}

function bh_log_done() {
  bh_log_wrap "\033[00;32m-- done\033[00m"
}

function bh_log_ok() {
  bh_log_wrap "\033[00;32m-- ok\033[00m"
}

function bh_log_try() {
  "$@"
  if $? -ne 0; then bh_log_error "$1" && exit 1; fi
}

# ---------------------------------------
# bashrc
# ---------------------------------------

function bh_bashrc_reload() {
  bh_log_func
  source $HOME/.bashrc
}

# ---------------------------------------
# test
# ---------------------------------------

function bh_test_and_create_folder() {
  if test ! -d $1; then
    bh_log_msg "creating $1"
    mkdir -p $1
  fi
}

function bh_test_and_create_file() {
  : ${1?"Usage: ${FUNCNAME[0]} [file]"}
  if ! test -f "$1"; then
    bh_test_and_create_folder $(dirname $1)
    touch "$1"
  fi
}

function bh_test_and_delete_dir() {
  if test -d $1; then rm -rf $1; fi
}

function bh_test_md5_compare() {
  : ${2?"Usage: ${FUNCNAME[0]} [file1] [file2]"}
  if [ $(md5sum $1 | awk '{print $1;exit}') == $(md5sum $2 | awk '{print $1;exit}') ]; then echo "same"; else echo "different"; fi
}

# ---------------------------------------
# curl
# ---------------------------------------

function bh_curl_get() {
  curl -i -s -X GET $1
}

function bh_curl_post() {
  curl -i -s -X POST $1
}

function bh_curl_post_json() {
  curl -i -s -X POST $1 --header 'Content-Type: application/json' --header 'Accept: application/json' -d "$2"
}

function bh_curl_fetch_to_dir() {
  curl -O $1 --create-dirs --output-dir $2
}

# ---------------------------------------
# decompress
# ---------------------------------------

function bh_decompress_zip() {
  : ${1?"Usage: ${FUNCNAME[0]} <zip-name>"}
  unzip $1 -d "${1%%.zip}"
}

function bh_decompress_zip_list() {
  : ${1?"Usage: ${FUNCNAME[0]} <zip-name>"}
  unzip -l $1
}

function bh_decompress() {
  : ${1?"Usage: ${FUNCNAME[0]} <zip-name> [folder-name]"}
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
    bh_log_error "$EXT is not supported compress." && exit
    ;;
  esac
}

function bh_decompress_from_url() {
  : ${2?"Usage: ${FUNCNAME[0]} <URL> <folder>"}
  local file_name="/tmp/$(basename $1)"

  if test ! -f $file_name; then
    bh_curl_fetch_to_dir $1 /tmp/
  fi
  echo "extracting $file_name to $2"
  bh_decompress $file_name $2
}

# ---------------------------------------
# diff
# ---------------------------------------

function bh_diff() {
  : ${2?"Usage: ${FUNCNAME[0]} <old_file> <new_file>"}
  diff "$1" "$2"
}

function bh_diff_apply() {
  : ${2?"Usage: ${FUNCNAME[0]} <patch> <targed_file>"}
  patch apply "$1" "$2"
}

# ---------------------------------------
# dotfiles
# ---------------------------------------

function bh_dotfiles_func() {
  : ${1?"Usage: ${FUNCNAME[0]} backup|install|diff"}
  bh_log_func
  declare -a files_array
  files_array=($BH_DOTFILES_BKPS)
  if [ ${#files_array[@]} -eq 0 ]; then
    bh_log_error "BH_DOTFILES_BKPS empty"
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
alias bh_dotfiles_install="bh_dotfiles_func install"
alias bh_dotfiles_backup="bh_dotfiles_func backup"
alias bh_dotfiles_diff="bh_dotfiles_func diff"

# ---------------------------------------
# home
# ---------------------------------------

function bh_home_clean_unused() {
  bh_log_func
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

function bh_home_dev_folder_git_repos() {
  bh_log_func

  # create dev dir
  bh_test_and_create_folder $BH_DEV
  local cwd=$(pwd)

  declare -a repos_array
  repos_array=($BH_DEV_REPOS)
  for ((i = 0; i < ${#repos_array[@]}; i = i + 2)); do
    local parent=$BH_DEV/${repos_array[$i]}
    local repo=${repos_array[$((i + 1))]}
    # create parent
    if ! test -d $parent; then
      bh_test_and_create_folder $parent
    fi
    # clone/pull repo
    local repo_basename="$(basename -s .git $repo)"
    local dst_folder="$parent/$repo_basename"
    if ! test -d "$dst_folder"; then
      bh_log_msg_2nd "clone $dst_folder"
      cd $parent
      git clone $repo
    else
      cd $dst_folder
      bh_log_msg_2nd "pull $dst_folder"
      git pull
    fi
  done
  cd $cwd
}

# ---------------------------------------
# rename
# ---------------------------------------

function bh_rename_to_prefix() {
  : ${2?"Usage: ${FUNCNAME[0]} <prefix> <files..>"}
  echo $@
  local prefix="$1"
  shift
  for i in "$@"; do mv $i $prefix$i; done
}

function bh_rename_to_lowercase_with_underscore() {
  : ${1?"Usage: ${FUNCNAME[0]} <file_name>"}
  echo "rename to lowercase with underscore"
  rename 'y/A-Z/a-z/' "$@"
  echo "replace '.', ' ', and '-' by '_''"
  rename 's/-+/_/g;s/\.+/_/g;s/ +/_/g' "$@"
}

function bh_rename_to_lowercase_with_dash() {
  : ${1?"Usage: ${FUNCNAME[0]} <file_name>"}
  echo "rename to lowercase with dash"
  rename 'y/A-Z/a-z/' "$@"
  echo "replace '.', ' ', and '-' by '_''"
  rename 's/_+/-/g;s/\.+/-/g;s/ +/-/g' "$@"
}

# ---------------------------------------
# user
# ---------------------------------------

function bh_user_sudo_nopasswd() {
  if ! test -d /etc/sudoers.d/; then bh_test_and_create_folder /etc/sudoers.d/; fi
  SET_USER=$USER && sudo sh -c "echo $SET_USER 'ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sudoers-user"
}

function bh_user_passwd_disable_len_restriction() {
  sudo sed -i 's/sha512/minlen=1 sha512/g' /etc/pam.d/common-password
}

function bh_user_permissions_opt() {
  bh_log_func
  sudo chown -R root:root /opt
  sudo chmod -R 775 /opt/
  grep root /etc/group | grep $USER >/dev/null
  newgrp root
}

function bh_user_lang_set_en() {
  local line='export LANG="en_US.UTF-8"'
  if ! grep -Fxq "$line" $HOME/.bashrc; then
    echo -e 'export LANG="en_US.UTF-8"' >>$HOME/.bashrc
    echo -e 'export LC_ALL="en_US.UTF-8"' >>$HOME/.bashrc
  fi
}

# ---------------------------------------
# folder
# ---------------------------------------

function bh_folder_sorted_by_size() {
  du -ahd 1 | sort -h
}

function bh_folder_info() {
  local extensions=$(for f in *.*; do printf "%s\n" "${f##*.}"; done | sort -u)
  echo "size="$(du -sh | awk '{print $1;exit}')
  echo "dirs="$(find . -mindepth 1 -maxdepth 1 -type d | wc -l)
  echo -n "files="$(find . -mindepth 1 -maxdepth 1 -type f | wc -l)"("
  for i in $extensions; do
    echo -n ".$i="$(find . -mindepth 1 -maxdepth 1 -type f -iname \*\.$i | wc -l)","
  done
  echo ")"
}

function bh_folder_find_duplicated_pdf() {
  find . -iname "*.pdf" -not -empty -type f -printf "%s\n" | sort -rn | uniq -d | xargs -I{} -n1 find . -type f -size {}c -print0 | xargs -r -0 md5sum | sort | uniq -w32 --all-repeated=separate
}

# ---------------------------------------
# mount
# ---------------------------------------

function bh_mount_list() {
  df -haT
}
