# ---------------------------------------
# essentials aliases
# ---------------------------------------
alias ls='ls --color=auto -I NTUSER\* -I ntuser\* -I AppData -I IntelGraphicsProfiles* -I MicrosoftEdgeBackups'
alias winget='winget.exe'
alias powershell='powershell.exe'
BH_PS1_DIR="$BH_DIR/lib/ps1/"
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
# explorer
# ---------------------------------------
function explorer() { explorer.exe $(cygpath -w $1); }

function explorer_restart() { powershell.exe "Stop-Process -ProcessName explorer -ea 0 | Out-Null"; }

function explorer_hide_home_dotfiles() { powershell -c 'Get-ChildItem "${env:userprofile}\\.*" | ForEach-Object { $_.Attributes += "Hidden" }'; }

function explorer_open_startup() { powershell -c 'explorer ${env:appdata}\Microsoft\Windows\Start Menu\Programs\Startup'; }

function explorer_open_recycle_bin() { powershell -c 'explorer shell:RecycleBinFolder'; }

# ---------------------------------------
# win upgrade
# ---------------------------------------

function win_upgrade() {
  gsudo powershell -c '
    Install-Module -Name PSWindowsUpdate -Force
    Install-WindowsUpdate -AcceptAll -IgnoreReboot
  '
}

# ---------------------------------------
# env
# ---------------------------------------

function win_env_show() {
  powershell -c '[System.Environment]::GetEnvironmentVariables()'
}

function win_env_add() {
  : ${2?"Usage: ${FUNCNAME[0]} <varname> <value>"}
  powershell -c "[System.Environment]::SetEnvironmentVariable('$1', '$2', 'user')"
}

# ---------------------------------------
# path add
# ---------------------------------------

function win_path_show() {
  powershell -c '(Get-ChildItem Env:Path).Value'
}

function win_path_show_as_list() {
  IFS=';' read -ra ADDR <<<$(win_path_show)
  for i in "${!ADDR[@]}"; do echo ${ADDR[$i]}; done
}

function win_path_add() { # using ps1 script
  local dir=$(cygpath -w $@)
  local dircyg=$(cygpath $@)
  # export in win
  powershell -command "$(cygpath -w $BH_PS1_DIR/path_add.ps1)" \'$dir\'
  # export in bash (it will reolad from win in new shell)
  if [[ ":$PATH:" != *":$dircyg:"* ]]; then export PATH=${PATH}:$dircyg; fi
}

# ---------------------------------------
# winget
# ---------------------------------------

function winget_upgrade_all() {
  winget upgrade --all --silent
}

function winget_install() {
  for i in "$@"; do
    winget list $i >/dev/null || winget install --accept-package-agreements --accept-source-agreements --silent $pkg
  done
}

# ---------------------------------------
# win sanity (ps1 scripts)
# ---------------------------------------

function win_sanity_ctx_menu() { gsudo powershell \'$(cygpath -w $BH_PS1_DIR/sanity_ctx_menu.ps1)\'; }
function win_sanity_password_policy() { gsudo powershell \'$(cygpath -w $BH_PS1_DIR/sanity_password_policy.ps1)\'; }
function win_sanity_services() { gsudo powershell \'$(cygpath -w $BH_PS1_DIR/sanity_services.ps1)\'; }
function win_sanity_this_pc() { gsudo powershell \'$(cygpath -w $BH_PS1_DIR/sanity_this_pc.ps1)\'; }
function win_sanity_ui() { gsudo powershell \'$(cygpath -w $BH_PS1_DIR/sanity_ui.ps1)\'; }

# ---------------------------------------
# msys2 (ps1 scripts)
# ---------------------------------------

function msys2_install() { gsudo powershell \'$(cygpath -w $BH_PS1_DIR/msys2_install.ps1)\'; }
function msys2_use_same_home() { gsudo powershell \'$(cygpath -w $BH_PS1_DIR/msys2_use_same_home.ps1)\'; }

# ---------------------------------------
# wsl (ps1 scripts)
# ---------------------------------------
function wsl_install() { gsudo powershell \'$(cygpath -w $BH_PS1_DIR/wsl_install.ps1)\'; }
function win_wsl_use_same_home() { gsudo powershell \'$(cygpath -w $BH_PS1_DIR/wsl_use_same_home.ps1)\'; }

# ---------------------------------------
# install
# ---------------------------------------

function win_install_ssh_client() {
  gsudo powershell -c '
    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
  '
}

function win_install_miktex() {
  winget_install ChristianSchenk.MiKTeX
  win_path_add $(cygpath -w $HOME/AppData/Local/Programs/MiKTeX/miktex/bin/x64/)
}

function win_install_ghostscript() {
  winget_install ArtifexSoftware.GhostScript
  win_path_add $(cygpath -w '/c/Program Files/gs/gs10.00.0/bin')
}

function win_install_make() {
  winget_install GnuWin32.Make
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

function win_install_flutter()  {
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
