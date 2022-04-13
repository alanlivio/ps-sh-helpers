# ---------------------------------------
# ubuntu_server
# ---------------------------------------

function ubu_server_tty1_autologing() {
  local file="/etc/systemd/system/getty@tty1.service.d/override.conf"
  sudo mkdir -p $(dirname $file)
  sudo touch $file
  echo '[Service]' | sudo tee $file
  echo 'ExecStart=' | sudo tee -a $file
  echo "ExecStart=-/sbin/agetty --noissue --autologin $USER %I $TERM" | sudo tee -a $file
  echo 'Type=idle' | sudo tee -a $file
}

# ---------------------------------------
# systemd
# ---------------------------------------

function ubu_systemd_list() {
  systemctl --type=service
}

function ubu_systemd_status_service() {
  : ${1?"Usage: ${FUNCNAME[0]} <service_name>"}
  systemctl status $1
}

function ubu_systemd_add_script() {
  : ${1?"Usage: ${FUNCNAME[0]} <service_file>"}
  systemctl daemon-reload
  systemctl enable $1
}

# ---------------------------------------
# ports
# ---------------------------------------

function ubu_ports_list() {
  lsof -i
}

function ubu_ports_kill_using() {
  : ${1?"Usage: ${FUNCNAME[0]} <port>"}
  local pid=$(sudo lsof -t -i:$1)
  if test -n "$pid"; then
    sudo kill -9 "$pid"
  fi
}

function ubu_ports_list_one() {
  : ${1?"Usage: ${FUNCNAME[0]} <port>"}
  sudo lsof -i:$1
}

# ---------------------------------------
# deb
# ---------------------------------------

function ubu_deb_install() {
  : ${1?"Usage: ${FUNCNAME[0]} <pkg_name>"}
  sudo dpkg -i $1
}

function ubu_deb_install_force_depends() {
  : ${1?"Usage: ${FUNCNAME[0]} <pkg_name>"}
  sudo dpkg -i --force-depends $1
}

function ubu_deb_info() {
  : ${1?"Usage: ${FUNCNAME[0]} <pkg_name>"}
  dpkg-deb --info $1
}

function ubu_deb_contents() {
  : ${1?"Usage: ${FUNCNAME[0]} <pkg_name>"}
  dpkg-deb --show $1
}

# ---------------------------------------
# apt helpers
# ---------------------------------------

function apt_upgrade() {
  log_func
  sudo apt -y update
  if [ "$(apt list --upgradable 2>/dev/null | wc -l)" -gt 1 ]; then
    sudo apt -y upgrade
  fi
}

function apt_update() {
  log_func
  sudo apt -y update
}

function apt_ppa_remove() {
  log_func
  sudo add-apt-repository --remove $1
}

function apt_ppa_list() {
  log_func
  apt policy
}

function apt_fixes() {
  log_func
  sudo dpkg --configure -a
  sudo apt install -f --fix-broken
  sudo apt-get update --fix-missing
  sudo apt dist-upgrade
}

function apt_install() {
  log_func

  local pkgs_to_install=""
  for i in "$@"; do
    dpkg --status "$i" &>/dev/null
    if test $? != 0; then
      pkgs_to_install="$pkgs_to_install $i"
    fi
  done
  if test ! -z "$pkgs_to_install"; then
    log_msg "pkgs_to_install=$pkgs_to_install"
    sudo apt install -y $pkgs_to_install
  fi
}

function apt_lastest_pkgs() {
  local pkgs=""
  for i in "$@"; do
    pkgs+=$(apt search $i 2>/dev/null | grep -E -o "^$i([0-9.]+)/" | cut -d/ -f1)
    pkgs+=" "
  done
  echo $pkgs
}

function apt_autoremove() {
  log_func
  if [ "$(apt --dry-run autoremove 2>/dev/null | grep -c -Po 'Remv \K[^ ]+')" -gt 0 ]; then
    sudo apt -y autoremove
  fi
}

function apt_remove_pkgs() {
  log_func
  local pkgs_to_remove=""
  for i in "$@"; do
    dpkg --status "$i" &>/dev/null
    if test $? -eq 0; then
      pkgs_to_remove="$pkgs_to_remove $i"
    fi
  done
  if test -n "$pkgs_to_remove"; then
    echo "pkgs_to_remove=$pkgs_to_remove"
    sudo apt remove -y --purge $pkgs_to_remove
  fi
}

function apt_remove_orphan_pkgs() {
  local pkgs_orphan_to_remove=""
  while [ "$(deborphan | wc -l)" -gt 0 ]; do
    for i in $(deborphan); do
      local found_exception=false
      for j in "$@"; do
        if test "$i" = "$j"; then
          found_exception=true
          return
        fi
      done
      if ! $found_exception; then
        pkgs_orphan_to_remove="$pkgs_orphan_to_remove $i"
      fi
    done
    echo "pkgs_orphan_to_remove=$pkgs_orphan_to_remove"
    if test -n "$pkgs_orphan_to_remove"; then
      sudo apt remove -y --purge $pkgs_orphan_to_remove
    fi
  done
}

function apt_fetch_install() {
  : ${1?"Usage: ${FUNCNAME[0]} <URL>"}
  local apt_name=$(basename $1)
  if test ! -f /tmp/$apt_name; then
    decompress_from_url $1 /tmp/
    if test $? != 0; then log_error "decompress_from_url failed." && return 1; fi
  fi
  sudo dpkg -i /tmp/$apt_name
}

# ---------------------------------------
# distro
# ---------------------------------------

function ubu_distro_upgrade() {
  sudo sed -i 's/Prompt=lts/Prompt=normal/g' /etc/update-manager/release-upgrades
  sudo apt update && sudo apt dist-upgrade
  do-release-upgrade
}

# ---------------------------------------
# install
# ---------------------------------------

function ubu_install_foxit() {
  log_func
  if ! type FoxitReader &>/dev/null; then
    local url=https://cdn01.foxitsoftware.com/pub/foxit/reader/desktop/linux/2.x/2.4/en_us/FoxitReader.enu.setup.2.4.4.0911.x64.run.tar.gz
    decompress_from_url $url /tmp/
    sudo /tmp/FoxitReader.enu.setup.2.4.4.0911\(r057d814\).x64.run
  fi
  if ! test -d $HELPERS_OPT/foxitsoftware; then
    sudo sed -i 's/^Icon=.*/Icon=\/usr\/share\/icons\/hicolor\/64x64\/apps\/FoxitReader.png/g' $HELPERS_OPT/foxitsoftware/foxitreader/FoxitReader.desktop
    sudo desktop-file-install $HELPERS_OPT/foxitsoftware/foxitreader/FoxitReader.desktop
  fi
}

function ubu_install_tor() {
  log_func
  if ! test -d $HELPERS_OPT/tor; then
    local url=https://dist.torproject.org/torbrowser/9.5/tor-browser-linux64-9.5_en-US.tar.xz
    decompress_from_url $url $HELPERS_OPT/
  fi
  if test $? != 0; then log_error "decompress_from_url failed." && return 1; fi
  mv $HELPERS_OPT/tor-browser_en-US $HELPERS_OPT/tor/
  sed -i "s|^Exec=.*|Exec=${HOME}/opt/tor/Browser/start-tor-browser|g" $HELPERS_OPT/tor/start-tor-browser.desktop
  sudo desktop-file-install "$HELPERS_OPT/tor/start-tor-browser.desktop"
}

function ubu_install_zotero() {
  log_func
  if ! test -d $HELPERS_OPT/zotero; then
    local url=https://download.zotero.org/client/release/5.0.82/Zotero-5.0.82_linux-x86_64.tar.bz2
    decompress_from_url $url /tmp/
    mv /tmp/Zotero_linux-x86_64 $HELPERS_OPT/zotero
  fi
  {
    echo '[Desktop Entry]'
    echo 'Version=1.0'
    echo 'Name=Zotero'
    echo 'Type=Application'
    echo "Exec=$HELPERS_OPT/zotero/zotero"
    echo "Icon=$HELPERS_OPT/zotero/chrome/icons/default/default48.png"
  } >$HELPERS_OPT/zotero/zotero.desktop
  sudo desktop-file-install $HELPERS_OPT/zotero/zotero.desktop
}

function ubu_install_texlive() {
  local pkgs_to_install+="texlive-base texlive-latex-recommended texlive-latex-extra texlive-bibtex-extra texlive-extra-utils texlive-fonts-extra texlive-xetex texlive-lang-english"
  apt_install $pkgs_to_install
}

function ubu_install_simplescreenrercoder_apt() {
  log_func
  if ! type simplescreenrecorder &>/dev/null; then
    sudo rm /etc/apt/sources.list.d/maarten-baert-ubuntu-simplescreenrecorder*
    sudo add-apt-repository -y ppa:maarten-baert/simplescreenrecorder
    sudo apt update
    sudo apt install -y simplescreenrecorder
  fi
}

function ubu_install_vscode() {
  log_func
  if ! type code &>/dev/null; then
    sudo rm /etc/apt/sources.list.d/vscode*
    curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor >/tmp/microsoft.gpg
    sudo install -o root -g root -m 644 /tmp/microsoft.gpg /etc/apt/trusted.gpg.d/
    sudo sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/vscode stable main" > /etc/apt/sources.list.d/vscode.list'
    sudo apt update
    sudo apt install -y code
  fi
}

function ubu_install_insync() {
  log_func
  dpkg --status insync &>/dev/null
  if test $? != 0; then
    sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys ACCAF35C
    echo "deb http://apt.insynchq.com/ubuntu bionic non-free contrib" | sudo tee /etc/apt/sources.list.d/insync.list
    sudo apt update
    sudo apt install -y insync insync-nautilus
  fi
}

function ubu_install_vidcutter() {
  log_func
  dpkg --status vidcutter &>/dev/null
  if test $? != 0; then
    sudo rm /etc/apt/sources.list.d/ozmartian*
    sudo add-apt-repository -y ppa:ozmartian/apps
    sudo apt update
    sudo apt install -y python3-dev vidcutter
  fi
}

function ubu_install_peek() {
  log_func
  dpkg --status peek &>/dev/null
  if test $? != 0; then
    sudo rm /etc/apt/sources.list.d/peek-developers*
    sudo add-apt-repository -y ppa:peek-developers/stable
    sudo apt update
    sudo apt install -y peek
  fi
}
