# ---------------------------------------
# load libs for specific commands
# ---------------------------------------

IS_GNOME=false
HAS_SNAP=false
if type gnome-shell &>/dev/null; then IS_GNOME=true; fi
if type snap &>/dev/null; then HAS_SNAP=true; fi
if $IS_GNOME; then source "$BH_DIR/ubuntu/gnome.sh"; fi
if $HAS_SNAP; then source "$BH_DIR/ubuntu/snap.sh"; fi
if type apt tar &>/dev/null; then source "$BH_DIR/ubuntu/apt.sh"; fi
if type systemctl tar &>/dev/null; then source "$BH_DIR/ubuntu/systemd.sh"; fi
if type service tar &>/dev/null; then source "$BH_DIR/ubuntu/initd.sh"; fi
if type lxc &>/dev/null; then source "$BH_DIR/ubuntu/lxc.sh"; fi
if type lsof &>/dev/null; then source "$BH_DIR/ubuntu/ports.sh"; fi
if test -z "$(sudo dmidecode | grep 'Apple')"; then "$BH_DIR/ubuntu/on_mac.sh"; fi

# ---------------------------------------
# setup/update_clean
# ---------------------------------------

function bh_setup_ubuntu() {
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
  bh_install_vscode
  bh_vscode_install_config_files
  # cleanup
  bh_home_clean_unused
}

function bh_update_clean_ubuntu() {
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

function bh_distro_upgrade() {
  sudo sed -i 's/Prompt=lts/Prompt=normal/g' /etc/update-manager/release-upgrades
  sudo apt update && sudo apt dist-upgrade
  do-release-upgrade
}

function bh_distro_ver() {
  lsb_release -a
}

# ---------------------------------------
# install
# ---------------------------------------

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

BH_FLUTTER_VER="2.2.3"

function bh_install_androidcmd_flutter() {
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
    bh_decompress_from_url $android_cmd_url $android_sdk_dir
    if test $? != 0; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
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
    bh_decompress_from_url $flutter_sdk_url $opt_dst
    if test $? != 0; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
    bh_path_add $flutter_sdk_dir/bin
  fi
}

# ---------------------------------------
# ubuntu_server helpers
# ---------------------------------------

function bh_server_tty1_autologing() {
  local file="/etc/systemd/system/getty@tty1.service.d/override.conf"
  sudo mkdir -p $(dirname $file)
  sudo touch $file
  echo '[Service]' | sudo tee $file
  echo 'ExecStart=' | sudo tee -a $file
  echo "ExecStart=-/sbin/agetty --noissue --autologin $USER %I $TERM" | sudo tee -a $file
  echo 'Type=idle' | sudo tee -a $file
}
