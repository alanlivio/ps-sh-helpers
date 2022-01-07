# ---------------------------------------
# ubu_install
# ---------------------------------------

function bh_ubu_install_foxit() {
  bh_log_func
  if ! type FoxitReader &>/dev/null; then
    local url=https://cdn01.foxitsoftware.com/pub/foxit/reader/desktop/linux/2.x/2.4/en_us/FoxitReader.enu.setup.2.4.4.0911.x64.run.tar.gz
    bh_decompress_from_url $url /tmp/
    sudo /tmp/FoxitReader.enu.setup.2.4.4.0911\(r057d814\).x64.run
  fi
  if ! test -d $HELPERS_OPT/foxitsoftware; then
    sudo sed -i 's/^Icon=.*/Icon=\/usr\/share\/icons\/hicolor\/64x64\/apps\/FoxitReader.png/g' $HELPERS_OPT/foxitsoftware/foxitreader/FoxitReader.desktop
    sudo desktop-file-install $HELPERS_OPT/foxitsoftware/foxitreader/FoxitReader.desktop
  fi
}

function bh_ubu_install_tor() {
  bh_log_func
  if ! test -d $HELPERS_OPT/tor; then
    local url=https://dist.torproject.org/torbrowser/9.5/tor-browser-linux64-9.5_en-US.tar.xz
    bh_decompress_from_url $url $HELPERS_OPT/
  fi
  if test $? != 0; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
  mv $HELPERS_OPT/tor-browser_en-US $HELPERS_OPT/tor/
  sed -i "s|^Exec=.*|Exec=${HOME}/opt/tor/Browser/start-tor-browser|g" $HELPERS_OPT/tor/start-tor-browser.desktop
  sudo desktop-file-install "$HELPERS_OPT/tor/start-tor-browser.desktop"
}

function bh_ubu_install_zotero() {
  bh_log_func
  if ! test -d $HELPERS_OPT/zotero; then
    local url=https://download.zotero.org/client/release/5.0.82/Zotero-5.0.82_linux-x86_64.tar.bz2
    bh_decompress_from_url $url /tmp/
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

function bh_ubu_install_texlive() {
  local pkgs_to_install+="texlive-base texlive-latex-recommended texlive-latex-extra texlive-bibtex-extra texlive-extra-utils texlive-fonts-extra texlive-xetex texlive-lang-english"
  bh_apt_install $pkgs_to_install
}

function bh_ubu_install_simplescreenrercoder_apt() {
  bh_log_func
  if ! type simplescreenrecorder &>/dev/null; then
    sudo rm /etc/apt/sources.list.d/maarten-baert-ubuntu-simplescreenrecorder*
    sudo add-apt-repository -y ppa:maarten-baert/simplescreenrecorder
    sudo apt update
    sudo apt install -y simplescreenrecorder
  fi
}

function bh_ubu_install_vscode() {
  bh_log_func
  if ! type code &>/dev/null; then
    sudo rm /etc/apt/sources.list.d/vscode*
    curl https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor >/tmp/microsoft.gpg
    sudo install -o root -g root -m 644 /tmp/microsoft.gpg /etc/apt/trusted.gpg.d/
    sudo sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/vscode stable main" > /etc/apt/sources.list.d/vscode.list'
    sudo apt update
    sudo apt install -y code
  fi
}

function bh_ubu_install_insync() {
  bh_log_func
  dpkg --status insync &>/dev/null
  if test $? != 0; then
    sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys ACCAF35C
    echo "deb http://apt.insynchq.com/ubuntu bionic non-free contrib" | sudo tee /etc/apt/sources.list.d/insync.list
    sudo apt update
    sudo apt install -y insync insync-nautilus
  fi
}

function bh_ubu_install_vidcutter() {
  bh_log_func
  dpkg --status vidcutter &>/dev/null
  if test $? != 0; then
    sudo rm /etc/apt/sources.list.d/ozmartian*
    sudo add-apt-repository -y ppa:ozmartian/apps
    sudo apt update
    sudo apt install -y python3-dev vidcutter
  fi
}

function bh_ubu_install_peek() {
  bh_log_func
  dpkg --status peek &>/dev/null
  if test $? != 0; then
    sudo rm /etc/apt/sources.list.d/peek-developers*
    sudo add-apt-repository -y ppa:peek-developers/stable
    sudo apt update
    sudo apt install -y peek
  fi
}
