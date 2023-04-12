#########################
# essentials aliases
#########################
alias ls='ls --color=auto -I NTUSER\* -I ntuser\* -I AppData -I IntelGraphicsProfiles* -I MicrosoftEdgeBackups'
alias winget='winget.exe'
alias powershell='powershell.exe'
BH_PS1_DIR="$BH_DIR/lib/ps1/"

#########################
# explorer open
#########################
function explorer_hide_home_dotfiles() { powershell -c 'Get-ChildItem "${env:userprofile}\\.*" | ForEach-Object { $_.Attributes += "Hidden" }'; }
function explorer_restart() { powershell "Stop-Process -ProcessName explorer -ea 0 | Out-Null"; }
function explorer_open_startmenu() { powershell -c 'explorer ${env:appdata}\Microsoft\Windows\Start Menu\Programs'; }
function explorer_open_startmenu_all_users() { powershell -c 'explorer ${env:programdata}\Microsoft\Windows\Start Menu\Programs'; }
function explorer_open_recycle_bin() { powershell -c 'explorer shell:RecycleBinFolder'; }

#########################
# win upgrade
#########################

function win_upgrade() {
  gsudo powershell.exe -c 'Install-Module -Name PSWindowsUpdate -Force; Install-WindowsUpdate -AcceptAll -IgnoreReboot'
}

#########################
# regedit
#########################

function regedit_open_path() {
  powershell -c "
    reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\ /v Lastkey /d 'Computer\\$1' /t REG_SZ /f
    regedit.exe
  "
}

function regedit_open_shell_folders() {
  regedit_open_path 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
}

#########################
# env
#########################

function win_env_show() {
  powershell -c '[System.Environment]::GetEnvironmentVariables()'
}

function win_env_add() {
  : ${2?"Usage: ${FUNCNAME[0]} <varname> <value>"}
  powershell -c "[System.Environment]::SetEnvironmentVariable('$1', '$2', 'user')"
}

#########################
# path add
#########################

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
  powershell -c "$(cygpath -w $BH_PS1_DIR/path_add.ps1)" \'$dir\'
  # export in bash (it will reolad from win in new shell)
  if [[ ":$PATH:" != *":$dircyg:"* ]]; then export PATH=${PATH}:$dircyg; fi
}

#########################
# winget
#########################

function winget_show_with_versions() {
  winget show --versions $1
}

function winget_upgrade_all() {
  winget upgrade --all --silent
}

function winget_install() {
  local pkgs_to_install=""
  for i in "$@"; do
    if [[ $(winget list --id $i) =~ "No installed"* ]]; then
      pkgs_to_install="$i $pkgs_to_install"
    fi
  done
  if test ! -z "$pkgs_to_install"; then
    echo "pkgs_to_install=$pkgs_to_install"
    for pkg in $pkgs_to_install; do
      winget install --accept-package-agreements --accept-source-agreements --silent $pkg
    done
  fi
}

#########################
# services
#########################

function services_reset_startup() { gsudo powershell.exe \'$(cygpath -w $BH_PS1_DIR/services_reset_startup.ps1)\'; }
function services_disable_unused() { gsudo powershell.exe \'$(cygpath -w $BH_PS1_DIR/services_disable_unused.ps1)\'; }

#########################
# sanity
#########################

function win_sanity_ctx_menu() { gsudo powershell.exe \'$(cygpath -w $BH_PS1_DIR/sanity_ctx_menu.ps1)\'; }
function win_sanity_password_policy() { gsudo powershell.exe \'$(cygpath -w $BH_PS1_DIR/sanity_password_policy.ps1)\'; }
function win_sanity_this_pc() { gsudo powershell.exe \'$(cygpath -w $BH_PS1_DIR/sanity_this_pc.ps1)\'; }
function win_sanity_ui() { gsudo powershell.exe \'$(cygpath -w $BH_PS1_DIR/sanity_ui.ps1)\'; }

#########################
# msys2
#########################

alias msys2_search='pacman -s --noconfirm'
alias msys2_show='pacman -Qi'
alias msys2_list_installed='pacman -Qqe'
alias msys2_install='pacman -S --noconfirm'
alias msys2_uninstall='pacman -R --noconfirm'

function win_install_msys2() { winget_install msys2.msys2; }
function msys2_use_same_home() { echo db_home: windows >>/etc/nsswitch.conf; }

#########################
# wsl
#########################

function win_install_wsl() { gsudo powershell.exe \'$(cygpath -w $BH_PS1_DIR/wsl_install.ps1)\'; }
function wsl_use_same_home() { gsudo powershell.exe \'$(cygpath -w $BH_PS1_DIR/wsl_use_same_home.ps1)\'; }
function wsl_code_from_win() {
  if [ "$#" -ne 0 ]; then
    powershell -c '& code ' "$@";
  else
    powershell -c '& code .';
  fi
}

#########################
# install
#########################

function win_add_slink_at_bin() {
  local link="$BH_BIN/$(basename $(cygpath $1))"
  link="$(cygpath -w $link)"
  local target="$(cygpath -w $1)"
  gsudo powershell.exe.exe -c "New-Item -ItemType SymbolicLink -Path" \'$link\' " -Target " \'$target\'
}

function win_install_ssh_client() {
  gsudo powershell.exe -c 'Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0'
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

function win_install_bat() {
  decompress_from_url_one_file_and_move_to_bin https://github.com/sharkdp/bat/releases/download/v0.22.1/bat-v0.22.1-x86_64-pc-windows-gnu.zip bat.exe
  return_if_last_command_fail
  win_path_add "$BH_BIN"
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
    if test $? != 0; then log_error "decompress_from_url failed." && return 1; fi
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
    if test $? != 0; then log_error "decompress_from_url failed." && return 1; fi
    win_path_add $(cygpath -w $flutter_sdk_dir/bin)
  else
    log_msg "$flutter_sdk_dir exist. skipping."
  fi
}
