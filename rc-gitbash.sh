#!/bin/bash

# ---------------------------------------
# var/alias
# ---------------------------------------

alias unixpath='cygpath'
alias winpath='cygpath -w'
# fix mingw tmp
unset temp
unset tmp
# hide windows user files when ls home
alias ls='ls --color=auto --hide=ntuser* --hide=NTUSER* --hide=AppData --hide=IntelGraphicsProfiles* --hide=MicrosoftEdgeBackups'
alias start="cmd.exe /c start"
alias choco='/c/ProgramData/chocolatey/bin/choco.exe'
alias chrome="/c/Program\ Files/Google/Chrome/Application/chrome.exe"
alias whereis='where'
alias reboot='gsudo shutdown \/r'
alias sudo='gsudo'
alias ps_call="powershell -c"
alias ps_call_admin="gsudo powershell -c"

# ---------------------------------------
# wrapper calls to libs-win/win.ps1
# ---------------------------------------
SCRIPT_PS_WPATH=$(unixpath -w "$BH_DIR/lib-win/setup.ps1")
function bh_ps_lib_call() {
  powershell.exe -command "& { . $SCRIPT_PS_WPATH; $* }"
}

function bh_ps_lib_call_admin() {
  sudo powershell.exe -command "& { . $SCRIPT_PS_WPATH;  $* }"
}

function bh_ps_def_func() {
  eval "function $1() { bh_ps_lib_call $*; }"
}

function bh_ps_def_func_admin() {
  eval "function $1()"'{ echo $*; bh_ps_lib_call_admin '"$1"' $*; }'
}

function bh_ps_test_command() {
  powershell -c '(Get-Command' "$1" '-ea 0) -ne $null'
}

# ---------------------------------------
# load libs for specific commands
# ---------------------------------------

if type tlshell.exe &>/dev/null; then source "$BH_DIR/lib-win/texlive.sh"; fi
if type wsl.exe &>/dev/null; then source "$BH_DIR/lib-win/wsl.sh"; fi

# ---------------------------------------
# setup/update_clean helpers
# ---------------------------------------

bh_ps_def_func_admin bh_setup_win
bh_ps_def_func_admin bh_setup_win_sanity

function bh_setup_win_common_user() {
  bh_log_func
  bh_setup_win_sanity
  bh_win_get_install Google.Chrome VideoLAN.VLC 7zip.7zip Piriform.CCleaner
}

function bh_update_clean_win() {
  # windows
  bh_ps_lib_call_admin "bh_win_sysupdate"
  bh_ps_lib_call_admin "bh_win_get_install $PKGS_WINGET"
  bh_ps_lib_call_admin "bh_appx_install $PKGS_APPX"
  bh_ps_lib_call_admin "bh_choco_install $PKGS_CHOCO"
  bh_choco_upgrade
  bh_choco_clean
  bh_python_upgrade
  bh_python_install $PKGS_PYTHON
  # vscode
  bh_vscode_install $PKGS_VSCODE
  # cleanup
  bh_home_clean_unused
  bh_home_hide_dotfiles
}

# ---------------------------------------
# msys helpers
# ---------------------------------------

bh_ps_def_func_admin bh_msys_add_to_path
bh_ps_def_func_admin bh_msys_sanity

# ---------------------------------------
# path helpers
# ---------------------------------------

function bh_win_path() {
  powershell -c "[Environment]::GetEnvironmentVariable('path', 'Machine')"
}

function bh_win_path_add() {
  local dir=$(winpath $1)
  bh_ps_lib_call "bh_path_add $dir"
}

# ---------------------------------------
# appx helpers
# ---------------------------------------

function bh_appx_list_installed() {
  sudo powershell -c "Get-AppxPackage -AllUsers | Select-Object Name, PackageFullName"
}

bh_ps_def_func_admin bh_appx_install
bh_ps_def_func_admin bh_appx_uninstall

function bh_appx_install_essentials() {
  local pkgs='Microsoft.WindowsStore Microsoft.WindowsCalculator Microsoft.Windows.Photos Microsoft.WindowsFeedbackHub Microsoft.WindowsCamera Microsoft.WindowsSoundRecorder'
  bh_appx_install $pkgs
}

# ---------------------------------------
# choco helpers
# ---------------------------------------

bh_ps_def_func_admin bh_choco_install
bh_ps_def_func_admin bh_choco_uninstall
bh_ps_def_func_admin bh_choco_list_installed
bh_ps_def_func_admin bh_choco_clean
bh_ps_def_func_admin bh_choco_delete_local_lib

function bh_choco_upgrade() {
  bh_log_func
  local outdated=false
  sudo choco outdated | grep '0 package' >/dev/null || outdated=true
  if $outdated; then sudo choco upgrade -y --acceptlicense all; fi
}

function bh_choco_list_installed() {
  choco list -l
}

function bh_choco_clean() {
  bh_log_func
  if type choco-cleaner.exe &>/dev/null; then
    sudo choco install choco-cleaner
  fi
  ps_call_admin 'Invoke-Expression "$env:ChocolateyToolsLocation\BCURRAN3\choco-cleaner.ps1" | Out-Null'
}

# ---------------------------------------
# winget helpers
# ---------------------------------------

bh_ps_def_func_admin bh_win_get_install
bh_ps_def_func_admin bh_win_get_uninstall
bh_ps_def_func_admin bh_win_get_upgrade

function bh_win_get_list_installed() {
  ps_lib_call '$(bh_win_get_installed).Split()'
}

function bh_win_get_list_installed_verbose() {
  winget list
}

function bh_win_get_settings() {
  winget settings
}

function bh_win_get_upgrade() {
  winget upgrade --all --silent
}

# ---------------------------------------
# home helpers
# ---------------------------------------

bh_ps_def_func_admin bh_explorer_restore_desktop

function bh_home_hide_dotfiles() {
  bh_log_func
  powershell -c 'Get-ChildItem "${env:userprofile}\.*" | ForEach-Object { $_.Attributes += "Hidden" }'
}

# ---------------------------------------
# keyboard
# ---------------------------------------

function bh_win_keyboard_lang_stgs_open() {
  cmd '/c rundll32.exe Shell32,Control_RunDLL input.dll,,{C07337D3-DB2C-4D0B-9A93-B722A6C106E2}'
}

# ---------------------------------------
# service
# ---------------------------------------

function bh_win_service_list_running() {
  ps_call_admin 'Get-Service | Where-Object { $_.Status -eq "Running" }'
}

function bh_win_service_list_enabled() {
  ps_call_admin 'Get-Service | Where-Object { $_.StartType -eq "Automatic" }'
}

function bh_win_service_list_disabled() {
  ps_call_admin 'Get-Service | Where-Object { $_.StartType -eq "Disabled" }'
}

# ---------------------------------------
# explorer
# ---------------------------------------

function bh_explorer_open_trash() {
  ps_call 'Start-Process explorer shell:recyclebinfolder'
}

function bh_explorer_restart() {
  ps_call_admin 'taskkill /f /im explorer.exe | Out-Null'
  ps_call 'Start-Process explorer.exe'
}

# ---------------------------------------
# env helpers
# ---------------------------------------

bh_ps_def_func_admin bh_env_add

# ---------------------------------------
# wt helpers
# ---------------------------------------
BH_WT_STGS="$HOME/AppData/Local/Packages/Microsoft.WindowsTerminal_8wekyb3d8bbwe/LocalState/settings.json"

function bh_wt_settings() {
  bh_ps_def_func bh_wt_settings
  code $BH_WT_STGS
}

# ---------------------------------------
# sysupdate helpers
# ---------------------------------------

function bh_win_sysupdate_list() {
  ps_call_admin 'Get-WindowsUpdate'
}

function bh_win_sysupdate_list_last_installed() {
  ps_call_admin 'Get-WUHistory -Last 10 | Select-Object Date, Title, Result'
}

# ---------------------------------------
# network
# ---------------------------------------

function bh_win_network_list_wifi_SSIDs() {
  ps_call 'netsh wlan show net mode=bssid'
}

function bh_win_network_set_max_users_port() {
  ps_call_admin 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\" -Name "MaxUserPort " -Value 0xffffffff'
}

# ---------------------------------------
# install helpers
# ---------------------------------------

bh_ps_def_func_admin bh_win_install_wsl_ubuntu
bh_ps_def_func_admin bh_win_install_msys

function bh_win_install_docker() {
  bh_log_func
  ps_call_admin Enable-WindowsOptionalFeature -Online -FeatureName $("Microsoft-Hyper-V") -All
  ps_call_admin Enable-WindowsOptionalFeature -Online -FeatureName $("Containers") -All
  bh_win_get_install Docker.DockerDesktop
}

function bh_win_install_tesseract() {
  bh_log_func
  if type tesseract.exe &>/dev/null; then
    bh_win_get_install tesseract
    bh_path_add 'C:\Program Files\Tesseract-OCR'
  fi
}

function bh_win_install_java() {
  bh_log_func
  if type java.exe &>/dev/null; then
    bh_win_get_install ojdkbuild.ojdkbuild
    local javahome=$(ps_call '$(get-command java).Source.replace("\bin\java.exe", "")')
    bh_env_add "JAVA_HOME" "$javahome"
  fi
}

function bh_win_install_msys() {
  bh_log_func
  if test -d '/c/msys64/'; then
    bh_win_get_install msys2.msys2
    bh_msys_sanity
  fi
}

function bh_win_install_battle_steam() {
  bh_log_func
  bh_win_get_install Blizzard.BattleNet Valve.Steam
}

BH_FLUTTER_VER="2.2.3"

function bh_win_install_windows_androidcmd_flutter() {
  bh_log_func

  # create opt
  local opt_dst="$BH_OPT_WIN/"
  bh_test_and_create_folder $opt_dst

  # android cmd and sdk
  local android_sdk_dir="$opt_dst/android"
  local android_cmd_dir="$android_sdk_dir/cmdline-tools"
  local android_cmd_url="https://dl.google.com/android/repository/commandlinetools-win-6858069_latest.zip"
  if ! test -d $android_cmd_dir; then
    bh_wget_extract $android_cmd_url $android_sdk_dir
    if test $? != 0; then bh_log_error "wget failed." && return 1; fi
    bh_ps_lib_call_admin "bh_path_add $(winpath $android_cmd_dir/bin)"
  fi
  if ! test -d $android_sdk_dir/platforms; then
    $android_cmd_dir/bin/sdkmanager.bat --sdk_root="$android_sdk_dir" --install 'platform-tools' 'platforms;android-29'
    yes | $android_cmd_dir/bin/sdkmanager.bat --sdk_root="$android_sdk_dir" --licenses
    bh_ps_lib_call_admin "bh_env_add ANDROID_HOME $(winpath $android_sdk_dir)"
    bh_ps_lib_call_admin "bh_env_add ANDROID_SDK_ROOT $(winpath $android_sdk_dir)"
    bh_ps_lib_call_admin "bh_path_add $(winpath $android_sdk_dir/platform-tools)"
  fi

  # flutter
  local flutter_sdk_dir="$opt_dst/flutter"
  local flutter_sdk_url="https://storage.googleapis.com/flutter_infra_release/releases/stable/windows/flutter_windows_${BH_FLUTTER_VER}-stable.zip"
  if ! test -d $flutter_sdk_dir; then
    # opt_dst beacuase zip extract the flutter dir
    bh_wget_extract $flutter_sdk_url $opt_dst
    if test $? != 0; then bh_log_error "wget failed." && return 1; fi
    bh_ps_lib_call_admin "bh_path_add $(winpath $flutter_sdk_dir/bin)"
  fi
}

function bh_win_install_windows_latexindent() {
  bh_log_func
  if ! type latexindent.exe &>/dev/null; then
    wget https://github.com/cmhughes/latexindent.pl/releases/download/V3.10/latexindent.exe -P /c/tools/
    wget https://raw.githubusercontent.com/cmhughes/latexindent.pl/main/defaultSettings.yaml -P /c/tools/
  fi
}

function bh_win_install_texlive() {
  sudo choco install texlive
}
