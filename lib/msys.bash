# ---------------------------------------
# msys
# ---------------------------------------

function msys_fix_home() {
  if ! test -d /mnt/; then mkdir /mnt/; fi
  echo -e "none / cygdrive binary,posix=0,noacl,user 0 0" | tee /etc/fstab
  echo -e "C:/Users /home ntfs binary,noacl,auto 1 1" | tee -a /etc/fstab
  echo -e "C:/Users /Users ntfs binary,noacl,auto 1 1" | tee -a /etc/fstab
  # use /mnt/c/ like in WSL
  echo -e "/c /mnt/c none bind" | tee -a /etc/fstab
  echo -e 'db_home: windows >> /etc/nsswitch.conf' | tee -a /etc/nsswitch.conf
}

function msys_search() {
  log_func
  pacman -Ss --noconfirm "$@"
}

function msys_show() {
  log_func
  pacman -Qi "$@"
}

function msys_list_installed() {
  log_func
  pacman -Qqe
}

function msys_install() {
  log_func
  pacman -Su --needed --noconfirm "$@"
}

function msys_install_force() {
  log_func
  pacman -Syu --noconfirm "$@"
}

function msys_uninstall() {
  log_func
  pacman -R --noconfirm "$@"
}

function msys_upgrade() {
  log_func
  pacman --needed -S bash pacman pacman-mirrors msys2-runtime
  pacman -Su --noconfirm
}

function msys_fix_lock() {
  log_func
  rm /var/lib/pacman/db.lck
}
