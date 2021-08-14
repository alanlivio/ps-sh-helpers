# ---------------------------------------
# vscode helpers
# ---------------------------------------

function bh_vscode_install_config_files() {
  if test -d $DOTFILES_VSCODE; then
    cp $DOTFILES_VSCODE/settings.json $HOME/.config/Code/User
    cp $DOTFILES_VSCODE/keybindings.json $HOME/.config/Code/User
  fi
}

function bh_vscode_diff() {
  : ${1?"Usage: ${FUNCNAME[0]} <old_file> <new_file>"}
  diff "$1" "$2" &>/dev/null
  if test $? -eq 1; then
    code --wait --diff "$1" "$2"
  fi
}

function bh_vscode_install() {
  bh_log_func
  local pkgs_to_install=""
  local pkgs_installed_tmp_file="/tmp/code-list-extensions"
  code --list-extensions >$pkgs_installed_tmp_file
  for i in "$@"; do
    grep -i "^$i" &>/dev/null <$pkgs_installed_tmp_file
    if test $? != 0; then
      pkgs_to_install="$i $pkgs_to_install"
    fi
  done
  if ! test -z $pkgs_to_install; then
    echo "pkgs_to_install=$pkgs_to_install"
    for i in $pkgs_to_install; do
      code --install-extension $i
    done
  fi
}
