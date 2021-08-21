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