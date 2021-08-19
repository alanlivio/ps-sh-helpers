# ---------------------------------------
# msys helpers
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