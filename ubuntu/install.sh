# ---------------------------------------
# install
# ---------------------------------------

BH_FLUTTER_VER="2.2.3"

function bh_install_ubuntu_androidcmd_flutter() {
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
# deb
# ---------------------------------------

if type deb tar &>/dev/null; then
  function bh_deb_install() {
    : ${1?"Usage: ${FUNCNAME[0]} <pkg_name>"}
    sudo dpkg -i $1
  }

  function bh_deb_install_force_depends() {
    : ${1?"Usage: ${FUNCNAME[0]} <pkg_name>"}
    sudo dpkg -i --force-depends $1
  }

  function bh_deb_info() {
    : ${1?"Usage: ${FUNCNAME[0]} <pkg_name>"}
    dpkg-deb --info $1
  }

  function bh_deb_contents() {
    : ${1?"Usage: ${FUNCNAME[0]} <pkg_name>"}
    dpkg-deb --show $1
  }
fi

if type apt &>/dev/null; then

  # ---------------------------------------
  # apt helpers
  # ---------------------------------------

  function bh_apt_upgrade() {
    bh_log_func
    sudo apt -y update
    if [ "$(apt list --upgradable 2>/dev/null | wc -l)" -gt 1 ]; then
      sudo apt -y upgrade
    fi
  }

  function bh_apt_update() {
    bh_log_func
    sudo apt -y update
  }

  function bh_apt_ppa_remove() {
    bh_log_func
    sudo add-apt-repository --remove $1
  }

  function bh_apt_ppa_list() {
    bh_log_func
    apt policy
  }

  function bh_apt_fixes() {
    bh_log_func
    sudo dpkg --configure -a
    sudo apt install -f --fix-broken
    sudo apt-get update --fix-missing
    sudo apt dist-upgrade
  }

  function bh_apt_install() {
    bh_log_func

    local pkgs_to_install=""
    for i in "$@"; do
      dpkg --status "$i" &>/dev/null
      if test $? != 0; then
        pkgs_to_install="$pkgs_to_install $i"
      fi
    done
    if test ! -z "$pkgs_to_install"; then
      bh_log_msg "pkgs_to_install=$pkgs_to_install"
      sudo apt install -y $pkgs_to_install
    fi
  }

  function bh_apt_lastest_pkgs() {
    local pkgs=""
    for i in "$@"; do
      pkgs+=$(apt search $i 2>/dev/null | grep -E -o "^$i([0-9.]+)/" | cut -d/ -f1)
      pkgs+=" "
    done
    echo $pkgs
  }

  function bh_apt_autoremove() {
    bh_log_func
    if [ "$(apt --dry-run autoremove 2>/dev/null | grep -c -Po 'Remv \K[^ ]+')" -gt 0 ]; then
      sudo apt -y autoremove
    fi
  }

  function bh_apt_remove_pkgs() {
    bh_log_func
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

  function bh_apt_remove_orphan_pkgs() {
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

  function bh_apt_fetch_install() {
    : ${1?"Usage: ${FUNCNAME[0]} <URL>"}
    local apt_name=$(basename $1)
    if test ! -f /tmp/$apt_name; then
      bh_decompress_from_url $1 /tmp/
      if test $? != 0; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
    fi
    sudo dpkg -i /tmp/$apt_name
  }

  # ---------------------------------------
  # distro
  # ---------------------------------------

  function bh_apt_distro_upgrade() {
    sudo sed -i 's/Prompt=lts/Prompt=normal/g' /etc/update-manager/release-upgrades
    sudo apt update && sudo apt dist-upgrade
    do-release-upgrade
  }

  # ---------------------------------------
  # install
  # ---------------------------------------

  function bh_install_ubuntu_docker() {
    bh_log_funch
    sudo apt-get install apt-transport-https ca-certificates curl gnupg lsb-release
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo \
      "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
        $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
    sudo apt-get update
    sudo apt-get install docker-ce docker-ce-cli containerd.io
  }
fi
