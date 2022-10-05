alias ls='ls --color=auto --hide=ntuser* --hide=NTUSER* --hide=AppData --hide=IntelGraphicsProfiles* --hide=MicrosoftEdgeBackups'
alias gsudo='/c/Program\ Files\ \(x86\)/gsudo/gsudo.exe'

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

function win_install_gitbash() {
  powershell $(cygpath -w $BH_DIR/lib/ps1/install_gitbash.ps1)
}

function win_install_msys2() {
  powershell $(cygpath -w $BH_DIR/lib/ps1/install_msys2.ps1)
}

function win_install_ghostscript() {
  win_get_install ArtifexSoftware.GhostScript
  win_path_add $(cygpath -w '/c/Program Files/gs/gs9.55.0/bin')
}

function win_install_make() {
  win_get_install GnuWin32.Make
  win_path_add "$PROGRAMFILES (x86)\GnuWin32\bin"
}

BH_AD_PLT_VER="33.0.3-windows"

function win_install_adb() {
  # android plataform tools
  local android_sdk_dir=$(cygpath $BH_BIN/Android/Sdk)
  test_and_create_dir $android_sdk_dir
  local android_plattools_dir="$android_sdk_dir/platform-tools"
  local android_plattools_url="https://dl.google.com/android/repository/platform-tools_r${BH_AD_PLT_VER}.zip"
  if ! test -d $android_plattools_dir; then
    decompress_from_url $android_plattools_url $android_sdk_dir
    if test $? != 0; then log_error "decompress_from_url failed." && exit; fi
    win_path_add $(cygpath -w $android_plattools_dir)
  else
    log_msg "$android_plattools_dir exist. skipping."
  fi
}

BH_AD_CMD_VER="8512546"
BH_AD_SDK_VER="33"

function win_install_android_sdk() {
  # android Command-line tools (sdkmanager)
  # https://developer.android.com/studio#command-tools
  local android_sdk_dir=$(cygpath $BH_BIN/Android/Sdk)
  test_and_create_dir $android_sdk_dir
  local android_cmd_dir="$android_sdk_dir/cmdline-tools"
  local android_cmd_url="https://dl.google.com/android/repository/commandlinetools-win-${BH_AD_CMD_VER}_latest.zip"
  if ! test -d $android_cmd_dir; then
    decompress_from_url $android_cmd_url $android_sdk_dir
    if test $? != 0; then log_error "decompress_from_url failed." && exit; fi
    win_path_add $(cygpath -w $android_cmd_dir/bin)
  else
    log_msg "$android_cmd_dir exist. skipping."
  fi
  # android SDK (sdkmanager)
  # https://developer.android.com/studio#command-tools
  if ! test -d "$android_sdk_dir/platforms/android-$BH_AD_SDK_VER"; then
    $android_cmd_dir/bin/sdkmanager.bat --sdk_root="$android_sdk_dir" --install  "platform-tools" "platforms;android-$BH_AD_SDK_VER"
    yes | $android_cmd_dir/bin/sdkmanager.bat --sdk_root="$android_sdk_dir" --licenses
    win_env_add ANDROID_HOME $(cygpath -w $android_sdk_dir)
    win_env_add ANDROID_SDK_ROOT $(cygpath -w $android_sdk_dir)
  else
    log_msg ""$android_sdk_dir/platforms/android-$BH_AD_SDK_VER" exist. skipping."
  fi
}

BH_FLUTTER_VER="3.0.5"

function win_install_flutter() {
  local dst="$BH_BIN"
  local flutter_sdk_dir="$BH_BIN/flutter"
  local flutter_sdk_url="https://storage.googleapis.com/flutter_infra_release/releases/stable/windows/flutter_windows_${BH_FLUTTER_VER}-stable.zip"
  if ! test -d $flutter_sdk_dir; then
    # to dst because zip extract to dst/flutter/
    decompress_from_url $flutter_sdk_url $dst
    if test $? != 0; then log_error "decompress_from_url failed." && exit; fi
  fi
  win_path_add $(cygpath -w $flutter_sdk_dir/bin)
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
# from ps1 scripts
# ---------------------------------------

function win_path_add() {
  local dir=$(cygpath -w $@)
  local dircyg=$(cygpath $@)
  # export in win
  powershell -command "$(cygpath -w $BH_DIR/lib/ps1/path_add.ps1)" \'$dir\'
  # export in bash (it will reolad from win in new shell)
  if [[ ":$PATH:" != *":$dircyg:"* ]]; then export PATH=${PATH}:$dircyg; fi
}

function win_install_msys() {  gsudo powershell \'$(cygpath -w $BH_DIR/lib/ps1/install_msys.ps1)\'; }
function win_install_winget() {  gsudo powershell \'$(cygpath -w $BH_DIR/lib/ps1/install_winget.ps1)\'; }
function win_install_wsl() {  gsudo powershell \'$(cygpath -w $BH_DIR/lib/ps1/install_wsl.ps1)\'; }

function win_sanity_ui() {  powershell \'$(cygpath -w $BH_DIR/lib/ps1/sanity_ui.ps1)\'; }
function win_sanity_ctx_menu() {  gsudo powershell \'$(cygpath -w $BH_DIR/lib/ps1/sanity_ctx_menu.ps1)\'; }
function win_sanity_services() {  gsudo powershell \'$(cygpath -w $BH_DIR/lib/ps1/sanity_services.ps1)\'; }
function win_sanity_password_policy() {  gsudo powershell \'$(cygpath -w $BH_DIR/lib/ps1/sanity_password_policy.ps1)\'; }
function win_sanity_this_pc() {  gsudo powershell \'$(cygpath -w $BH_DIR/lib/ps1/sanity_this_pc.ps1)\'; }

function win_wsl_use_same_home() {  gsudo powershell \'$(cygpath -w $BH_DIR/lib/ps1/wsl_use_same_home.ps1)\'; }
function win_msys2_use_same_home() {  gsudo powershell \'$(cygpath -w $BH_DIR/lib/ps1/msys2_use_same_home.ps1)\'; }
