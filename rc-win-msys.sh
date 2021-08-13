# ---------------------------------------
# msys helpers
# ---------------------------------------

function bh_msys_admin_bash() {
  bh_log_func
  MSYS_CMD="C:\\msys64\\msys2_shell.cmd -defterm -mingw64 -no-start -use-full-path -here"
  sudo $MSYS_CMD
}

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
  sudo pacman -Su --needed --noconfirm "$@"
}

function bh_msys_install_force() {
  bh_log_func
  sudo pacman -Syu --noconfirm "$@"
}

function bh_msys_uninstall() {
  bh_log_func
  sudo pacman -R --noconfirm "$@"
}

function bh_msys_upgrade() {
  bh_log_func
  sudo pacman --needed -S bash pacman pacman-mirrors msys2-runtime
  sudo pacman -Su --noconfirm
}

function bh_msys_fix_lock() {
  bh_log_func
  sudo rm /var/lib/pacman/db.lck
}

function bh_msys_sanity() {
  bh_ps_call_admin "bh_msys_sanity"
}

function bh_setup_msys() {
  bh_user_permissions_sudo_nopasswd
  # update runtime
  PKGS="pacman pacman-mirrors msys2-runtime "
  # essentials
  PKGS+="$PKGS_ESSENTIALS "
  # python
  PKGS+="python-pip "
  bh_msys_install $PKGS
}
