# ---------------------------------------
# home
# ---------------------------------------

function bh_home_backup_func() {
  : ${1?"Usage: ${FUNCNAME[0]} save|restore|diff"}
  bh_log_func
  declare -a files_array
  files_array=($BH_HOME_BKPS)
  if [ ${#files_array[@]} -eq 0 ]; then
    bh_log_error "BH_HOME_BKPS empty"
  fi
  for ((i = 0; i < ${#files_array[@]}; i = i + 2)); do
    bh_test_and_create_file ${files_array[$i]}
    bh_test_and_create_file ${files_array[$((i + 1))]}
    if [ $1 = "save" ]; then
      cp ${files_array[$i]} ${files_array[$((i + 1))]}
    elif [ $1 = "restore" ]; then
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
alias bh_home_backup_restore="bh_home_backup_func restore"
alias bh_home_backup_save="bh_home_backup_func save"
alias bh_home_backup_diff="bh_home_backup_func diff"

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