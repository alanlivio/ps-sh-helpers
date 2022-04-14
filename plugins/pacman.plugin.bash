# ---------------------------------------
# pacman
# ---------------------------------------

function pacman_search() {
  pacman -Ss --noconfirm "$@"
}

function pacman_show() {
  pacman -Qi "$@"
}

function pacman_list_installed() {
  pacman -Qqe
}

function pacman_install() {
  pacman -Su --needed --noconfirm "$@"
}

function pacman_install_force() {
  pacman -Syu --noconfirm "$@"
}

function pacman_uninstall() {
  pacman -R --noconfirm "$@"
}
