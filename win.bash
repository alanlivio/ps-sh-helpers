alias ls='ls --color=auto -I NTUSER\* -I ntuser\* -I AppData -I IntelGraphicsProfiles* -I MicrosoftEdgeBackups'

# ---------------------------------------
# msys2
# ---------------------------------------

# pacman
alias msys2_search='pacman -Ss --noconfirm'
alias msys2_show='pacman -Qi'
alias msys2_list_installed='pacman -Qqe'
alias msys2_install='pacman -Su --needed --noconfirm'
alias msys2_install_force='pacman -Syu --noconfirm'
alias msys2_uninstall='pacman -R --noconfirm'

function msys2_same_home() {
  if ! test -d /mnt/; then mkdir /mnt/; fi
  echo -e "none / cygdrive binary,posix=0,noacl,user 0 0" | tee /etc/fstab
  echo -e "C:/Users /home ntfs binary,noacl,auto 1 1" | tee -a /etc/fstab
  echo -e "C:/Users /Users ntfs binary,noacl,auto 1 1" | tee -a /etc/fstab
  # use /mnt/c/ like in WSL
  echo -e "/c /mnt/c none bind" | tee -a /etc/fstab
  echo -e 'db_home: windows >> /etc/nsswitch.conf' | tee -a /etc/nsswitch.conf
}

# ---------------------------------------
# home/sys/path
# ---------------------------------------

function win_hide_home_dotfiles() { powershell -c 'Get-ChildItem "${env:userprofile}\\.*" | ForEach-Object { $_.Attributes += "Hidden" }'; }

function win_is_user_admin() {
  # ex: if [ $(win_is_user_admin) = "True" ]; then ...
  powershell -c ' (Get-LocalGroupMember "Administrators").Name -contains "$env:COMPUTERNAME\$env:USERNAME" '
}

function win_is_shell_eleveated() { # return True/False
  powershell -c '(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'
}

function win_sys_upgrade() {
  gsudo powershell -c '
    Install-Module -Name PSWindowsUpdate -Force
    Install-WindowsUpdate -AcceptAll -IgnoreReboot
  '
}

function win_env_show() {
  powershell -c 'Get-ChildItem Env:'
}

function win_env_add() {
  : ${2?"Usage: ${FUNCNAME[0]} <varname> <value>"}
  powershell -c "[System.Environment]::SetEnvironmentVariable('$1', '$2', 'user')"
}

function win_path_show() {
  powershell -c '(Get-ChildItem Env:Path).Value'
}

function win_path_show_as_list() {
  IFS=';' read -ra ADDR <<<$(win_path_show)
  for i in "${!ADDR[@]}"; do echo ${ADDR[$i]}; done
}

# ---------------------------------------
# winget
# ---------------------------------------

function win_get_list() {
  winget list
}

function win_get_settings() {
  winget settings
}

function win_get_upgrade() {
  winget upgrade --all --silent
}

function win_get_install() {
  local pkgs_to_install=""
  for i in "$@"; do
    if [[ $(winget list --id $i) =~ "No installed"* ]]; then
      pkgs_to_install="$i $pkgs_to_install"
    fi
  done
  if test ! -z "$pkgs_to_install"; then
    echo "pkgs_to_install=$pkgs_to_install"
    for pkg in $pkgs_to_install; do
      winget install $pkg
    done
  fi
}

# ---------------------------------------
# install
# ---------------------------------------

function win_install_python() {
  winget install Python.Python.3 --source winget -i
  win_path_add $(cygpath -w $HOME/AppData/Local/Programs/Python/Python310/Scripts/)
  win_path_add $(cygpath -w $HOME/AppData/Roaming/Python/Python310/Scripts/)
}

function win_install_miktex() {
  win_get_install ChristianSchenk.MiKTeX
  win_path_add $(cygpath -w $HOME/AppData/Local/Programs/MiKTeX/miktex/bin/x64/)
}

function win_install_ghostscript() {
  win_get_install ArtifexSoftware.GhostScript
  win_path_add $(cygpath -w '/c/Program Files/gs/gs9.55.0/bin')
}

function win_install_make() {
  win_get_install GnuWin32.Make
  win_path_add "$PROGRAMFILES (x86)\GnuWin32\bin"
}

function win_install_android_sdkmanager_and_platform_tools() {
  # create SDK_HOME
  local ad_sdk_home=$(cygpath $BH_BIN/Android/Sdk)
  test_and_create_dir $ad_sdk_home

  # android Command-line tools (sdkmanager)
  # https://developer.android.com/studio#command-tools
  local ad_cmd_ver="8512546"
  local ad_cmd_dir="$ad_sdk_home/cmdline-tools/latest"
  local ad_cmd_url="https://dl.google.com/android/repository/commandlinetools-win-${ad_cmd_ver}_latest.zip"
  if ! test -d $ad_cmd_dir; then
    # It is expected be at <sdk>/cmdline-tools/latest. othersie, `sdkmanager.bat --update`` gives:
    #    Error: Could not determine SDK root.
    #    Error: Either specify it explicitly with --sdk_root= or move this package into its expected location: <sdk>\cmdline-tools\latest\
    # Here, we extract and then rename the folder
    decompress_from_url $ad_cmd_url "$ad_sdk_home/cmdline-tools/"
    mv -f "$ad_sdk_home/cmdline-tools/cmdline-tools" $ad_cmd_dir
    if test $? != 0; then
      log_error "decompress_from_url failed."
      return 1
    fi
    win_path_add $(cygpath -w $ad_cmd_dir/bin)
    win_env_add ANDROID_HOME $(cygpath -w $ad_sdk_home)
    # install platform-tools
    sdkmanager.bat "platform-tools"
    # list installed
  else
    log_msg "$ad_cmd_dir exist. skipping."
  fi
  sdkmanager.bat --list_installed
}

function win_install_android_sdk() {
  if ! type sdkmanager.bat >/dev/null; then win_install_android_cmd_tools; fi
  local android_sdk_ver="33"
  yes | sdkmanager.bat "platforms;android-$android_sdk_ver"
  sdkmanager.bat --list_installed
}

BH_FLUTTER_VER="3.3.3"

function win_install_flutter() {
  local dst="$BH_BIN"
  local flutter_sdk_dir="$BH_BIN/flutter"
  local flutter_sdk_url="https://storage.googleapis.com/flutter_infra_release/releases/stable/windows/flutter_windows_${BH_FLUTTER_VER}-stable.zip"
  if ! test -d $flutter_sdk_dir; then
    # to dst because zip extract to dst/flutter/
    decompress_from_url $flutter_sdk_url $dst
    if test $? != 0; then
      log_error "decompress_from_url failed."
      return 1
    fi
    win_path_add $(cygpath -w $flutter_sdk_dir/bin)
  else
    log_msg "$flutter_sdk_dir exist. skipping."
  fi
}

function win_install_java() {
  if ! type java.exe &>/dev/null; then
    win_get_install ojdkbuild.ojdkbuild
    local javahome=$(powershell -c '$(get-command java).Source.replace("\bin\java.exe", "")')
    env_add "JAVA_HOME" "$javahome"
  fi
}

function win_install_docker() {
  gsudo powershell -c Enable-WindowsOptionalFeature -Online -FeatureName $("Microsoft-Hyper-V") -All
  gsudo powershell -c Enable-WindowsOptionalFeature -Online -FeatureName $("Containers") -All
  win_get_install Docker.DockerDesktop
}

# ---------------------------------------
# install from ps1 scripts
# ---------------------------------------

function win_install_msys2() { gsudo powershell \'$(cygpath -w $BH_DIR/lib/ps1/install_msys2.ps1)\'; }
function win_install_winget_latest() { powershell $(cygpath -w $BH_DIR/lib/ps1/install_winget_latest.ps1); }
function win_install_wsl() { gsudo powershell \'$(cygpath -w $BH_DIR/lib/ps1/install_wsl.ps1)\'; }

# ---------------------------------------
# others from ps1 scripts
# ---------------------------------------

function win_path_add() {
  local dir=$(cygpath -w $@)
  local dircyg=$(cygpath $@)
  # export in win
  powershell -command "$(cygpath -w $BH_DIR/lib/ps1/path_add.ps1)" \'$dir\'
  # export in bash (it will reolad from win in new shell)
  if [[ ":$PATH:" != *":$dircyg:"* ]]; then export PATH=${PATH}:$dircyg; fi
}

function win_msys2_use_same_home() { gsudo powershell \'$(cygpath -w $BH_DIR/lib/ps1/msys2_use_same_home.ps1)\'; }
function win_sanity_ctx_menu() { gsudo powershell \'$(cygpath -w $BH_DIR/lib/ps1/sanity_ctx_menu.ps1)\'; }
function win_sanity_password_policy() { gsudo powershell \'$(cygpath -w $BH_DIR/lib/ps1/sanity_password_policy.ps1)\'; }
function win_sanity_services() { gsudo powershell \'$(cygpath -w $BH_DIR/lib/ps1/sanity_services.ps1)\'; }
function win_sanity_this_pc() { gsudo powershell \'$(cygpath -w $BH_DIR/lib/ps1/sanity_this_pc.ps1)\'; }
function win_sanity_ui() { powershell \'$(cygpath -w $BH_DIR/lib/ps1/sanity_ui.ps1)\'; }
function win_wsl_use_same_home() { gsudo powershell \'$(cygpath -w $BH_DIR/lib/ps1/wsl_use_same_home.ps1)\'; }
