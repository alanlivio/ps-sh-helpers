# ---------------------------------------
# update_clean
# ---------------------------------------

function bh_update_cleanup_msys() {
  bh_log_func
  # windows
  if [ "$(bh_win_user_check_admin)" == "True" ]; then
    bh_win_sysupdate_win
  fi
  # essentials
  local pkgs="pacman pacman-mirrors msys2-runtime vim diffutils curl $BH_PKGS_MSYS"
  # python
  pkgs+="python-pip "
  bh_msys_install $pkgs
  bh_msys_upgrade
  # python
  $HAS_PYTHON && bh_python_install $BH_PKGS_PYTHON
  # cleanup
  bh_home_clean_unused
}

# ---------------------------------------
# msys
# ---------------------------------------

function bh_msys_search() {
  bh_log_func
  pacman -Ss --noconfirm "$@"
}

function bh_msys_show() {
  bh_log_func
  pacman -Qi "$@"
}

function bh_msys_list_installed() {
  bh_log_func
  pacman -Qqe
}

function bh_msys_install() {
  bh_log_func
  pacman -Su --needed --noconfirm "$@"
}

function bh_msys_install_force() {
  bh_log_func
  pacman -Syu --noconfirm "$@"
}

function bh_msys_uninstall() {
  bh_log_func
  pacman -R --noconfirm "$@"
}

function bh_msys_upgrade() {
  bh_log_func
  pacman --needed -S bash pacman pacman-mirrors msys2-runtime
  pacman -Su --noconfirm
}

function bh_msys_fix_lock() {
  bh_log_func
  rm /var/lib/pacman/db.lck
}