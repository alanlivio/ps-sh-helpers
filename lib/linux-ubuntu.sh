# ---------------------------------------
# install
# ---------------------------------------

function bh_install_bluetooth_audio() {
  sudo apt nstall pulseaudio pulseaudio-utils pavucontrol pulseaudio-module-bluetooth rtbth-dkms
}

function bh_install_bb_warsaw() {
  bh_log_func
  if ! type warsaw &>/dev/null; then
    bh_apt_fetch_install https://cloud.gastecnologia.com.br/bb/downloads/ws/warsaw_setup64.deb
  fi
}

function bh_install_git_lfs() {
  bh_log_func
  if ! type git-lfs &>/dev/null; then
    curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | sudo bash
    sudo apt-get install git-lfs
  fi
}

function bh_install_gitkraken() {
  bh_log_func
  if ! type gitkraken &>/dev/null; then
    sudo apt install gconf2 gconf-service libgtk2.0-0
    bh_apt_fetch_install https://release.axocdn.com/linux/gitkraken-amd64.deb
  fi
}

function bh_install_neo4j() {
  bh_log_func
  if ! type neo4j &>/dev/null; then
    wget -O - https://debian.neo4j.org/neotechnology.gpg.key | sudo apt-key add -
    echo 'deb https://debian.neo4j.org/repo stable/' | sudo tee /etc/apt/sources.list.d/neo4j.list
    sudo apt update
    sudo apt install neo4j
  fi
}

function bh_install_sqlworkbench() {
  bh_log_func
  dpkg --status mysql-workbench-community &>/dev/null
  if test $? != 0; then
    sudo apt install libzip5
    bh_apt_fetch_install https://cdn.mysql.com//Downloads/MySQLGUITools/mysql-workbench-community_8.0.17-1ubuntu19.04_amd64.deb
  fi
}

function bh_install_slack_deb() {
  bh_log_func
  dpkg --status slack-desktop &>/dev/null
  if test $? != 0; then
    sudo apt install -y libappindicator1
    bh_apt_fetch_install https://downloads.slack-edge.com/linux_releases/slack-desktop-4.0.2-amd64.deb
  fi
}

function bh_install_simplescreenrercoder_apt() {
  bh_log_func
  if ! type simplescreenrecorder &>/dev/null; then
    sudo rm /etc/apt/sources.list.d/maarten-baert-ubuntu-simplescreenrecorder*
    sudo add-apt-repository -y ppa:maarten-baert/simplescreenrecorder
    sudo apt update
    sudo apt install -y simplescreenrecorder
  fi
}

function bh_install_vscode() {
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

function bh_install_insync() {
  bh_log_func
  dpkg --status insync &>/dev/null
  if test $? != 0; then
    sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys ACCAF35C
    echo "deb http://apt.insynchq.com/ubuntu bionic non-free contrib" | sudo tee /etc/apt/sources.list.d/insync.list
    sudo apt update
    sudo apt install -y insync insync-nautilus
  fi
}

function bh_install_foxit() {
  bh_log_func
  if ! type FoxitReader &>/dev/null; then
    URL=https://cdn01.foxitsoftware.com/pub/foxit/reader/desktop/linux/2.x/2.4/en_us/FoxitReader.enu.setup.2.4.4.0911.x64.run.tar.gz
    bh_wget_extract $URL /tmp/
    sudo /tmp/FoxitReader.enu.setup.2.4.4.0911\(r057d814\).x64.run
  fi
  if ! test -d $HELPERS_OPT/foxitsoftware; then
    sudo sed -i 's/^Icon=.*/Icon=\/usr\/share\/icons\/hicolor\/64x64\/apps\/FoxitReader.png/g' $HELPERS_OPT/foxitsoftware/foxitreader/FoxitReader.desktop
    sudo desktop-file-install $HELPERS_OPT/foxitsoftware/foxitreader/FoxitReader.desktop
  fi
}

function bh_install_tor() {
  bh_log_func
  if ! test -d $HELPERS_OPT/tor; then
    URL=https://dist.torproject.org/torbrowser/9.5/tor-browser-linux64-9.5_en-US.tar.xz
    bh_wget_extract $URL $HELPERS_OPT/
  fi
  if test $? != 0; then bh_log_error "wget failed." && return 1; fi
  mv $HELPERS_OPT/tor-browser_en-US $HELPERS_OPT/tor/
  sed -i "s|^Exec=.*|Exec=${HOME}/opt/tor/Browser/start-tor-browser|g" $HELPERS_OPT/tor/start-tor-browser.desktop
  sudo desktop-file-install "$HELPERS_OPT/tor/start-tor-browser.desktop"
}

function bh_install_zotero() {
  bh_log_func
  if ! test -d $HELPERS_OPT/zotero; then
    URL=https://download.zotero.org/client/release/5.0.82/Zotero-5.0.82_linux-x86_64.tar.bz2
    bh_wget_extract $URL /tmp/
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

function bh_install_vidcutter() {
  bh_log_func
  dpkg --status vidcutter &>/dev/null
  if test $? != 0; then
    sudo rm /etc/apt/sources.list.d/ozmartian*
    sudo add-apt-repository -y ppa:ozmartian/apps
    sudo apt update
    sudo apt install -y python3-dev vidcutter
  fi
}

function bh_install_peek() {
  bh_log_func
  dpkg --status peek &>/dev/null
  if test $? != 0; then
    sudo rm /etc/apt/sources.list.d/peek-developers*
    sudo add-apt-repository -y ppa:peek-developers/stable
    sudo apt update
    sudo apt install -y peek
  fi
}

function bh_install_docker() {
  bh_log_funch
  sudo apt-get install apt-transport-https ca-certificates curl gnupg lsb-release
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
  echo \
    "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
        $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update
  sudo apt-get install docker-ce docker-ce-cli containerd.io
}

function bh_install_texlive() {
  local pkgs_to_install+="texlive-base texlive-latex-recommended texlive-latex-extra texlive-bibtex-extra texlive-extra-utils texlive-fonts-extra texlive-xetex texlive-lang-english"
  bh_apt_install $pkgs_to_install
}

function bh_install_node() {
  bh_log_funch
  curl -sL https://deb.nodesource.com/setup_13.x | sudo -E bash -
  sudo apt install -y nodejs
}

function bh_install_python35() {
  bh_log_func
  if ! type python3.5 &>/dev/null; then
    sudo apt install make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev python-openssl
    local cwd=$(pwd)
    cd /tmp
    bh_wget_extract https://www.python.org/ftp/python/3.5.7/Python-3.5.7.tgz /tmp
    cd /tmp/Python-3.5.7
    sudo ./configure --enable-optimizations
    make
    sudo make altinstall
    cd $cwd
  fi
}

function bh_install_luarocks() {
  bh_log_func
  if ! type luarocks &>/dev/null; then
    wget https://luarocks.org/releases/luarocks-3.3.0.tar.gz
    tar zxpf luarocks-3.3.0.tar.gz
    cd luarocks-3.3.0
    ./configure && make && sudo make install
  fi
}

BH_FLUTTER_VER="2.2.3"

function bh_install_androidcmd_flutter() {
  bh_log_func

  # create opt
  local OPT_DST="$HELPERS_OPT_LINUX"
  bh_test_and_create_folder $OPT_DST

  # android cmd and sdk
  local ANDROID_SDK_DIR="$OPT_DST/android"
  local ANDROID_CMD_DIR="$ANDROID_SDK_DIR/cmdline-tools"
  local ANDROID_CMD_URL="https://dl.google.com/android/repository/commandlinetools-linux-6858069_latest.zip"
  if ! test -d $ANDROID_CMD_DIR; then
    bh_test_and_create_folder $ANDROID_CMD_DIR
    bh_wget_extract $ANDROID_CMD_URL $ANDROID_SDK_DIR
    if test $? != 0; then bh_log_error "wget failed." && return 1; fi
    bh_path_add $ANDROID_CMD_DIR/bin/
  fi
  if ! test -d $ANDROID_SDK_DIR/platforms; then
    $ANDROID_CMD_DIR/bin/sdkmanager --sdk_root="$ANDROID_SDK_DIR" --install 'platform-tools' 'platforms;android-29'
    yes | $ANDROID_CMD_DIR/bin/sdkmanager --sdk_root="$ANDROID_SDK_DIR" --licenses
    bh_env_add ANDROID_HOME $ANDROID_SDK_DIR
    bh_env_add ANDROID_SDK_ROOT $ANDROID_SDK_DIR
    bh_path_add $ANDROID_SDK_DIR/platform-tools
  fi

  # flutter
  local FLUTTER_SDK_DIR="$OPT_DST/flutter"
  local FLUTTER_SDK_URL="https://storage.googleapis.com/flutter_infra/releases/stable/linux/flutter_${BH_FLUTTER_VER}-stable.tar.xz"
  if ! test -d $FLUTTER_SDK_DIR; then
    # OPT_DST beacuase zip extract the flutter dir
    bh_wget_extract $FLUTTER_SDK_URL $OPT_DST
    if test $? != 0; then bh_log_error "wget failed." && return 1; fi
    bh_path_add $FLUTTER_SDK_DIR/bin
  fi
}

# ---------------------------------------
# ubuntu
# ---------------------------------------

function bh_ubuntu_distro_upgrade() {
  sudo sed -i 's/Prompt=lts/Prompt=normal/g' /etc/update-manager/release-upgrades
  sudo apt update && sudo apt dist-upgrade
  do-release-upgrade
}

function bh_ubuntu_distro() {
  lsb_release -a
}

# ---------------------------------------
# system
# ---------------------------------------

function bh_system_product_name() {
  sudo dmidecode -s system-product-name
}

function bh_system_host() {
  hostnamectl
}

function bh_system_list_gpu() {
  lspci -nn | grep -E 'VGA|Display'
}

function bh_services_initd_list() {
  service --status-all
}

function bh_services_initd_enable() {
  : ${1?"Usage: ${FUNCNAME[0]} <script_file>"}$1
  sudo update-rc.d $1 enable
}

function bh_services_initd_disable() {
  : ${1?"Usage: ${FUNCNAME[0]} <script_file>"}$1
  sudo service $1 stop
  sudo update-rc.d -f $1 disable
}

function bh_services_systemd_list() {
  systemctl --type=service
}

function bh_services_systemd_status_service() {
  : ${1?"Usage: ${FUNCNAME[0]} <service_name>"}
  systemctl status $1
}

function bh_services_systemd_add_script() {
  : ${1?"Usage: ${FUNCNAME[0]} <service_file>"}
  systemctl daemon-reload
  systemctl enable $1
}

# ---------------------------------------
# user helpers
# ---------------------------------------

function bh_user_tty1_autologing() {
  local file="/etc/systemd/system/getty@tty1.service.d/override.conf"
  sudo mkdir -p $(dirname $file)
  sudo touch $file
  echo '[Service]' | sudo tee $file
  echo 'ExecStart=' | sudo tee -a $file
  echo "ExecStart=-/sbin/agetty --noissue --autologin $USER %I $TERM" | sudo tee -a $file
  echo 'Type=idle' | sudo tee -a $file
}

function bh_user_create_new() {
  : ${1?"Usage: ${FUNCNAME[0]} <user_name>"}
  sudo adduser "$1"
}

function bh_user_logout() {
  : ${1?"Usage: ${FUNCNAME[0]} <user_name>"}
  sudo skill -KILL -u $1
}

# ---------------------------------------
# x11
# ---------------------------------------

function bh_x11_properties_of_window() {
  xprop | grep "^WM_"
}

function bh_x11_properties_of_window() {
  xprop | grep "^WM_"
}

function bh_update_clean_ubuntu() {
  # snap
  bh_snap_install $PKGS_SNAP
  bh_snap_install_classic $PKGS_SNAP_CLASSIC
  bh_snap_upgrade
  bh_apt_upgrade
  # apt
  bh_apt_install $PKGS_APT
  bh_apt_remove_pkgs $PKGS_REMOVE_APT
  bh_apt_autoremove
  bh_apt_remove_orphan_pkgs $PKGS_APT_ORPHAN_EXPECTIONS
  # python
  bh_python_upgrade
  bh_python_install $PKGS_PYTHON
  # vscode
  bh_vscode_install $PKGS_VSCODE
  # cleanup
  bh_home_clean_unused_dirs
}

function bh_setup_ubuntu() {
  bh_log_func
  # sudo nopasswd
  bh_user_permissions_sudo_nopasswd
  # shell configure
  if type gnome-shell &>/dev/null; then
    bh_gnome_dark
    bh_gnome_sanity
    bh_gnome_disable_unused_apps_in_search
    bh_gnome_disable_super_workspace_change
  fi
  # cleanup
  bh_home_clean_unused_dirs
  # vim/git/essentials
  PKGS="git deborphan apt-file $PKGS_ESSENTIALS "
  # python
  PKGS+="python3 python3-pip "
  bh_apt_install $PKGS
  # set python3 as default
  bh_python_set_python3_default
  # install vscode
  bh_install_vscode
  bh_vscode_install_config_files
}
