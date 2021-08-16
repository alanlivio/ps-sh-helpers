# ---------------------------------------
# load libs for specific commands
# ---------------------------------------

IS_GNOME=false
HAS_SNAP=false
if type gnome-shell &>/dev/null; then IS_GNOME=true; fi
if type snap &>/dev/null; then HAS_SNAP=true; fi
if $IS_GNOME; then source "$BH_DIR/lib-ubuntu/gnome.sh"; fi
if $HAS_SNAP; then source "$BH_DIR/lib-ubuntu/snap.sh"; fi
if type apt tar &>/dev/null; then source "$BH_DIR/lib-ubuntu/apt.sh"; fi
if type systemctl tar &>/dev/null; then source "$BH_DIR/lib-ubuntu/systemd.sh"; fi
if type service tar &>/dev/null; then source "$BH_DIR/lib-ubuntu/initd.sh"; fi
if type lxc &>/dev/null; then source "$BH_DIR/lib-ubuntu/lxc.sh"; fi
if type lsof &>/dev/null; then source "$BH_DIR/lib-ubuntu/ports.sh"; fi
if test -z "$(sudo dmidecode | grep 'Apple')"; then "$BH_DIR/lib-ubuntu/on_mac.sh"; fi

# ---------------------------------------
# setup/update_clean
# ---------------------------------------

function bh_ubuntu_setup() {
  bh_log_func
  # gnome configure
  if $IS_GNOME; then
    bh_gnome_dark
    bh_gnome_sanity
    bh_gnome_disable_unused_apps_in_search
    bh_gnome_disable_super_workspace_change
  fi
  # essentials
  local pkgs="git deborphan apt-file $BH_PKGS_ESSENTIALS "
  # python
  pkgs+="python3 python3-pip "
  bh_apt_install $pkgs
  # set python3 as default
  bh_python_set_python3_default
  # install vscode
  bh_ubuntu_install_vscode
  bh_vscode_install_config_files
  # cleanup
  bh_home_clean_unused
}

function bh_ubuntu_update_clean() {
  if $HAS_SNAP; then
    # snap
    bh_snap_install $PKGS_SNAP
    bh_snap_install_classic $PKGS_SNAP_CLASSIC
    bh_snap_upgrade
    bh_apt_upgrade
  fi
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
  bh_home_clean_unused
}

# ---------------------------------------
# distro
# ---------------------------------------

function bh_ubuntu_distro_upgrade() {
  sudo sed -i 's/Prompt=lts/Prompt=normal/g' /etc/update-manager/release-upgrades
  sudo apt update && sudo apt dist-upgrade
  do-release-upgrade
}

function bh_ubuntu_distro_ver() {
  lsb_release -a
}

# ---------------------------------------
# ubuntu_install
# ---------------------------------------

if $IS_GNOME; then

  function bh_ubuntu_install_foxit() {
    bh_log_func
    if ! type FoxitReader &>/dev/null; then
      local url=https://cdn01.foxitsoftware.com/pub/foxit/reader/desktop/linux/2.x/2.4/en_us/FoxitReader.enu.setup.2.4.4.0911.x64.run.tar.gz
      bh_wget_extract $url /tmp/
      sudo /tmp/FoxitReader.enu.setup.2.4.4.0911\(r057d814\).x64.run
    fi
    if ! test -d $HELPERS_OPT/foxitsoftware; then
      sudo sed -i 's/^Icon=.*/Icon=\/usr\/share\/icons\/hicolor\/64x64\/apps\/FoxitReader.png/g' $HELPERS_OPT/foxitsoftware/foxitreader/FoxitReader.desktop
      sudo desktop-file-install $HELPERS_OPT/foxitsoftware/foxitreader/FoxitReader.desktop
    fi
  }

  function bh_ubuntu_install_tor() {
    bh_log_func
    if ! test -d $HELPERS_OPT/tor; then
      local url=https://dist.torproject.org/torbrowser/9.5/tor-browser-linux64-9.5_en-US.tar.xz
      bh_wget_extract $url $HELPERS_OPT/
    fi
    if test $? != 0; then bh_log_error "wget failed." && return 1; fi
    mv $HELPERS_OPT/tor-browser_en-US $HELPERS_OPT/tor/
    sed -i "s|^Exec=.*|Exec=${HOME}/opt/tor/Browser/start-tor-browser|g" $HELPERS_OPT/tor/start-tor-browser.desktop
    sudo desktop-file-install "$HELPERS_OPT/tor/start-tor-browser.desktop"
  }

  function bh_ubuntu_install_zotero() {
    bh_log_func
    if ! test -d $HELPERS_OPT/zotero; then
      local url=https://download.zotero.org/client/release/5.0.82/Zotero-5.0.82_linux-x86_64.tar.bz2
      bh_wget_extract $url /tmp/
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

  function bh_ubuntu_install_docker() {
    bh_log_funch
    sudo apt-get install apt-transport-https ca-certificates curl gnupg lsb-release
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo \
      "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
        $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
    sudo apt-get update
    sudo apt-get install docker-ce docker-ce-cli containerd.io
  }

  function bh_ubuntu_install_texlive() {
    local pkgs_to_install+="texlive-base texlive-latex-recommended texlive-latex-extra texlive-bibtex-extra texlive-extra-utils texlive-fonts-extra texlive-xetex texlive-lang-english"
    bh_apt_install $pkgs_to_install
  }

  function bh_ubuntu_install_simplescreenrercoder_apt() {
    bh_log_func
    if ! type simplescreenrecorder &>/dev/null; then
      sudo rm /etc/apt/sources.list.d/maarten-baert-ubuntu-simplescreenrecorder*
      sudo add-apt-repository -y ppa:maarten-baert/simplescreenrecorder
      sudo apt update
      sudo apt install -y simplescreenrecorder
    fi
  }

  function bh_ubuntu_install_vscode() {
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

  function bh_ubuntu_install_insync() {
    bh_log_func
    dpkg --status insync &>/dev/null
    if test $? != 0; then
      sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys ACCAF35C
      echo "deb http://apt.insynchq.com/ubuntu bionic non-free contrib" | sudo tee /etc/apt/sources.list.d/insync.list
      sudo apt update
      sudo apt install -y insync insync-nautilus
    fi
  }

  function bh_ubuntu_install_vidcutter() {
    bh_log_func
    dpkg --status vidcutter &>/dev/null
    if test $? != 0; then
      sudo rm /etc/apt/sources.list.d/ozmartian*
      sudo add-apt-repository -y ppa:ozmartian/apps
      sudo apt update
      sudo apt install -y python3-dev vidcutter
    fi
  }

  function bh_ubuntu_install_peek() {
    bh_log_func
    dpkg --status peek &>/dev/null
    if test $? != 0; then
      sudo rm /etc/apt/sources.list.d/peek-developers*
      sudo add-apt-repository -y ppa:peek-developers/stable
      sudo apt update
      sudo apt install -y peek
    fi
  }

fi

BH_FLUTTER_VER="2.2.3"

function bh_ubuntu_install_androidcmd_flutter() {
  bh_log_func

  # create opt
  local opt_dst="$BH_OPT_LINUX"
  bh_test_and_create_folder $opt_dst

  # android cmd and sdk
  local android_sdk_dir="$opt_dst/android"
  local android_cmd_dir="$android_sdk_dir/cmdline-tools"
  local android_cmd_url="https://dl.google.com/android/repository/commandlinetools-linux-6858069_latest.zip"
  if ! test -d $android_cmd_dir; then
    bh_test_and_create_folder $android_cmd_dir
    bh_wget_extract $android_cmd_url $android_sdk_dir
    if test $? != 0; then bh_log_error "wget failed." && return 1; fi
    bh_path_add $android_cmd_dir/bin/
  fi
  if ! test -d $android_sdk_dir/platforms; then
    $android_cmd_dir/bin/sdkmanager --sdk_root="$android_sdk_dir" --install 'platform-tools' 'platforms;android-29'
    yes | $android_cmd_dir/bin/sdkmanager --sdk_root="$android_sdk_dir" --licenses
    bh_env_add ANDROID_HOME $android_sdk_dir
    bh_env_add ANDROID_SDK_ROOT $android_sdk_dir
    bh_path_add $android_sdk_dir/platform-tools
  fi

  # flutter
  local flutter_sdk_dir="$opt_dst/flutter"
  local flutter_sdk_url="https://storage.googleapis.com/flutter_infra/releases/stable/linux/flutter_${BH_FLUTTER_VER}-stable.tar.xz"
  if ! test -d $flutter_sdk_dir; then
    # opt_dst beacuase zip extract the flutter dir
    bh_wget_extract $flutter_sdk_url $opt_dst
    if test $? != 0; then bh_log_error "wget failed." && return 1; fi
    bh_path_add $flutter_sdk_dir/bin
  fi
}

# ---------------------------------------
# ubuntu_server helpers
# ---------------------------------------

function bh_ubuntu_server_tty1_autologing() {
  local file="/etc/systemd/system/getty@tty1.service.d/override.conf"
  sudo mkdir -p $(dirname $file)
  sudo touch $file
  echo '[Service]' | sudo tee $file
  echo 'ExecStart=' | sudo tee -a $file
  echo "ExecStart=-/sbin/agetty --noissue --autologin $USER %I $TERM" | sudo tee -a $file
  echo 'Type=idle' | sudo tee -a $file
}
