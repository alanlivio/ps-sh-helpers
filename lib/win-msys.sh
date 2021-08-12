# ---------------------------------------
# msys funcs
# ---------------------------------------

function hf_msys_admin_bash() {
  hf_log_func
  MSYS_CMD="C:\\msys64\\msys2_shell.cmd -defterm -mingw64 -no-start -use-full-path -here"
  sudo $MSYS_CMD
}

function hf_msys_search() {
  hf_log_func
  pacman -Ss --noconfirm "$@"
}

function hf_msys_show() {
  hf_log_func
  pacman -Qi "$@"
}

function hf_msys_list_installed() {
  hf_log_func
  pacman -Qqe
}

function hf_msys_install() {
  hf_log_func
  sudo pacman -Su --needed --noconfirm "$@"
}

function hf_msys_install_force() {
  hf_log_func
  sudo pacman -Syu --noconfirm "$@"
}

function hf_msys_uninstall() {
  hf_log_func
  sudo pacman -R --noconfirm "$@"
}

function hf_msys_upgrade() {
  hf_log_func
  sudo pacman --needed -S bash pacman pacman-mirrors msys2-runtime
  sudo pacman -Su --noconfirm
}

function hf_msys_fix_lock() {
  hf_log_func
  sudo rm /var/lib/pacman/db.lck
}

function hf_msys_sanity() {
  hf_ps_call_admin "hf_msys_sanity"
}

function hf_setup_msys() {
  hf_user_permissions_sudo_nopasswd
  # update runtime
  PKGS="pacman pacman-mirrors msys2-runtime "
  # essentials
  PKGS+="$PKGS_ESSENTIALS "
  # python
  PKGS+="python-pip "
  hf_msys_install $PKGS
}
