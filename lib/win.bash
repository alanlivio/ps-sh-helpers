#!/bin/bash
# ---------------------------------------
# aliases
# ---------------------------------------

alias unixpath='cygpath'
alias winpath='cygpath -w'
# fix mingw tmp
unset temp
unset tmp
alias chrome="/c/Program\ Files/Google/Chrome/Application/chrome.exe"
alias ghostscript='gswin64c'
alias reboot='gsudo shutdown \/r'
if ! type pwsh &>/dev/null; then
  alias powershell="powershell"
fi
alias ps_call="powershell -c"
alias ps_call_admin="gsudo powershell -c"
function ps_call_script() { powershell -c "& { . $1}"; }
function ps_call_script_admin() { gsudo powershell -c "& { . $1}"; }
function bh_open { ps_call "Start-Process ${1:-.}"; }
if type gsudo &>/dev/null; then HAS_GSUDO=true; else HAS_GSUDO=false; fi

# ---------------------------------------
# gitbash
# ---------------------------------------

function bh_win_gitbash_fix_prompt {
  bh_log_func
  sed 's/show\sMSYSTEM/#&/g' -i /etc/profile.d/git-prompt.sh
  sed "s/PS1=\"\$PS1\"'\\\\n/#&/g" -i /etc/profile.d/git-prompt.sh
}

function bh_win_gitbash_open_prompt {
  bh_log_func
  bh_open "$(winpath /etc/profile.d/git-prompt.sh)"
}

# ---------------------------------------
# recycle_bin
# ---------------------------------------

function bh_win_recycle_bin_clean() {
  bh_log_func
  ps_call 'Clear-RecycleBin -Confirm:$false 2> $null'
}

# ---------------------------------------
# sound
# ---------------------------------------

function bh_win_sound_open_settings() {
  rundll32.exe shell32.dll,control_rundll mmsys.cpl,,2
}

# ---------------------------------------
# user
# ---------------------------------------

function bh_win_wt_open_settings() {
  bh_wt_stgs="$HOME/AppData/Local/Packages/Microsoft.WindowsTerminal_8wekyb3d8bbwe/LocalState/settings.json"
  code $bh_wt_stgs
}

# ---------------------------------------
# user
# ---------------------------------------

function bh_win_user_check_admin_group() {
  # usage if [ "$(bh_win_user_check_admin_group)" == "True" ]; then <commands>; fi
  ps_call '
    $user = "$env:COMPUTERNAME\$env:USERNAME"
    $group = "Administrators"
    (Get-LocalGroupMember $group).Name -contains $user
  '
}

function bh_win_user_check_eleveated_shell() {
  ps_call '(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)' | tr -d '\rn'
}

function bh_win_user_adminstrator_enable() {
  ps_call_admin 'net user administrator /active:yes'
}

function bh_win_user_adminstrator_disable() {
  ps_call_admin 'net user administrator /active:no'
}

# ---------------------------------------
# sysupdate
# ---------------------------------------

function bh_win_sysupdate_win() {
  bh_log_func
  ps_call_admin '
    Install-Module -Name PSWindowsUpdate -Force
    $(Install-WindowsUpdate -AcceptAll -IgnoreReboot) | Where-Object { 
    if ($_ -is [string]) {
      $_.Split("", [System.StringSplitOptions]::RemoveEmptyEntries) 
    } 
  }'
}

function bh_win_sysupdate_win_list() {
  ps_call_admin 'Get-WindowsUpdate'
}

function bh_win_sysupdate_win_list_last_installed() {
  ps_call_admin 'Get-WUHistory -Last 10 | Select-Object Date, Title, Result'
}

# ---------------------------------------
# feature
# ---------------------------------------

function bh_win_feature_enable_ssh_server_bash() {
  bh_log_func
  local current_bash_path=$(where bash | head -1)
  ps_call_admin "
    Add-WindowsCapability -Online -Name OpenSSH.Client
    Add-WindowsCapability -Online -Name OpenSSH.Server
    Start-Service sshd
    Set-Service -Name sshd -StartupType 'Automatic'
    New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value '$current_bash_path' -PropertyType String -Force
  "
}

function bh_win_feature_list_enabled() {
  bh_log_msg "WindowsOptionalFeatures"
  ps_call_admin 'Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Enabled"}'
  bh_log_msg "WindowsCapabilities"
  ps_call_admin 'Get-WindowsCapability -Online | Where-Object {$_.State -eq "Installed"}'
}

function bh_win_feature_list_disabled() {
  bh_log_msg "WindowsOptionalFeatures"
  ps_call_admin 'Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Disabled"}'
  bh_log_msg "WindowsCapabilities"
  ps_call_admin 'Get-WindowsCapability -Online | Where-Object {$_.State -eq "NotPresent"}'
}

# ---------------------------------------
# appx
# ---------------------------------------

function bh_win_appx_list_installed() {
  ps_call_admin "Get-AppxPackage -AllUsers | Select-Object Name, PackageFullName"
}

function bh_win_appx_uninstall() {
  ps_call_admin '
  if (Get-AppxPackage -Name ' "$1" ') {
    Get-AppxPackage' "$1" '| Remove-AppxPackage
  }
  '
}

function bh_win_appx_install() {
  ps_call_admin '
    Get-AppxPackage ' "$1" '| ForEach-Object { Add-AppxPackage -ea 0 -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" } | Out-null
  '
}

# ---------------------------------------
# services
# ---------------------------------------

function bh_win_services_list_running() {
  ps_call_admin 'Get-Service | Where-Object {$_.Status -eq "Running"}'
}

# ---------------------------------------
# env
# ---------------------------------------

function bh_win_env_show() {
  ps_call 'Get-ChildItem Env:'
}

function bh_win_env_add() {
  : ${2?"Usage: ${FUNCNAME[0]} <varname> <value>"}
  ps_call "[System.Environment]::SetEnvironmentVariable('$1', '$2', 'user')"
}

# ---------------------------------------
# path
# ---------------------------------------

function bh_win_path_show() {
  ps_call '(Get-ChildItem Env:Path).Value'
}

function bh_win_path_show_as_list() {
  IFS=';' read -ra ADDR <<<$(bh_win_path_show)
  for i in "${!ADDR[@]}"; do echo ${ADDR[$i]}; done
}

function bh_win_path_add() {
  local dir=$(winpath $@)
  ps_call ' 
    function bh_win_path_add($addDir) {
      $currentpath = [System.Environment]::GetEnvironmentVariable("PATH", "user")
      $regexAddPath = [regex]::Escape($addDir)
      $arrPath = $currentpath -split ";" | Sort-Object -Unique | Where-Object { $_ -notMatch "^$regexAddPath\\?" }
      $newpath = ($arrPath + $addDir) -join ";"
      [System.Environment]::SetEnvironmentVariable("PATH", $newpath, "user")
    }; bh_win_path_add ' \"$dir\"
}

function bh_win_path_remove() {
  local dir=$(winpath $@)
  ps_call ' 
    function bh_win_path_remove($remDir) {
      $currentpath = [System.Environment]::GetEnvironmentVariable("PATH", "user")
      $newpath = ($currentpath.Split(";") | Where-Object { $_ -ne "$remDir" }) -join ";"
      [System.Environment]::SetEnvironmentVariable("PATH", $newpath, "user")
    }; bh_win_path_remove ' \"$dir\"
}

function bh_win_path_add_winapps() {
  bh_win_path_add "$HOME/AppData/Local/Microsoft/WindowsApps/"
}

function bh_win_path_open_settings() {
  rundll32 sysdm.cpl,EditEnvironmentVariables &
}

# ---------------------------------------
# update_clean
# ---------------------------------------

function bh_update_cleanup_win() {
  bh_log_func
  # update bh
  bh_bh_update_if_needed
  # cleanup
  bh_home_clean_unused
  bh_win_explorer_hide_home_dotfiles
  # py
  $HAS_PY && bh_py_install $BH_WIN_PY
  $HAS_PY && bh_py_upgrade
  # vscode
  $HAS_VSCODE && bh_vscode_install $BH_WIN_VSCODE
  # win
  $HAS_GSUDO && bh_win_sysupdate_win
  # winget (it uses --scope=user)
  bh_win_get_install $BH_WIN_GET
}

# ---------------------------------------
# install
# ---------------------------------------

function bh_win_install_store_essentials() {
  local pkgs='Microsoft.WindowsStore Microsoft.WindowsCalculator Microsoft.Windows.Photos Microsoft.WindowsFeedbackHub Microsoft.WindowsCamera Microsoft.WindowsSoundRecorder'
  for pkg in $pkgs; do
    ps_call "
      Get-AppxPackage $pkg | ForEach-Object { Add-AppxPackage -ea 0 -DisableDevelopmentMode -Register \"\$(\$_.InstallLocation)\AppXManifest.xml\" } | Out-null
    "
  done
}

function bh_win_install_python() {
  winget install Python.Python.3 --source winget -i
  bh_win_path_add $(winpath $HOME/AppData/Local/Programs/Python/Python310/Scripts/)
  bh_win_path_add $(winpath $HOME/AppData/Roaming/Python/Python310/Scripts/)
}

function bh_win_install_miktex() {
  bh_win_get_install ChristianSchenk.MiKTeX
  bh_win_path_add $(winpath $HOME/AppData/Local/Programs/MiKTeX/miktex/bin/x64/)
}

function bh_win_install_zotero() {
  bh_win_get_install Zotero.Zotero
}

function bh_win_install_gitforwindows_and_wt() {
  ps_call_script $(unixpath -w $BH_DIR/lib/ps1/install-gitforwindows-and-wt.ps1)
}

function bh_win_install_msys() {
  ps_call_script $(unixpath -w $BH_DIR/lib/ps1/install-msys.ps1)
}

function bh_win_install_ghostscript() {
  bh_win_get_install ArtifexSoftware.GhostScript
  bh_win_path_add $(winpath '/c/Program Files/gs/gs9.55.0/bin')
}

function bh_win_install_vscode() {
  bh_win_get_install Microsoft.VisualStudioCode
}

function bh_win_install_cmake() {
  bh_win_get_install Kitware.CMake
}

function bh_win_install_pgrep() {
  local url="https://soft.rubypdf.com/download/pdfgrep/pdfgrep-1.4.0-win32.zip"
  local bin_dir="$BH_OPT/pdfgrep"
  if ! test -f $bin_dir; then
    bh_decompress_from_url $url $bin_dir
    if test $? != 0; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
  fi
  bh_win_path_add $(winpath $bin_dir)
}

function bh_win_install_make() {
  local url="https://jztkft.dl.sourceforge.net/project/ezwinports/make-4.3-without-guile-w32-bin.zip"
  local bin_dir="$BH_OPT/make-4.3-without-guile-w32-bin"
  if ! test -d $bin_dir; then
    bh_test_and_create_dir $bin_dir
    bh_decompress_from_url $url $bin_dir # no root dir
    if test $? != 0; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
  fi
  bh_win_path_add $(winpath $bin_dir/bin)
}

BH_FFMPEG_VER="4.4"
function bh_win_install_ffmpeg() {
  local url="https://www.gyan.dev/ffmpeg/builds/packages/ffmpeg-${BH_FFMPEG_VER}-essentials_build.zip"
  local bin_dir="$BH_OPT/ffmpeg-${BH_FFMPEG_VER}-essentials_build/bin/"
  if ! test -d $bin_dir; then
    bh_decompress_from_url $url $BH_OPT/ # has root dir
    if [[ $? != 0 || ! -d $bin_dir ]]; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
  fi
  bh_win_path_add $(winpath $bin_dir)
}

BH_NODE_VER="14.17.5"
function bh_win_install_node() {
  local url="https://nodejs.org/dist/v${BH_NODE_VER}/node-v${BH_NODE_VER}-win-x64.zip"
  local bin_dir="$BH_OPT/node-v${BH_NODE_VER}-win-x64"
  if ! test -d $bin_dir; then
    bh_test_and_create_dir $bin_dir # no root dir
    bh_decompress_from_url $url $BH_OPT
    if test $? != 0; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
  fi
  bh_win_env_add 'NODEJS_HOME' $(winpath $bin_dir)
  bh_win_path_add $(winpath $bin_dir)
}

BH_FLUTTER_VER="2.2.3"
BH_PLATOOLS_VER="31.0.3-windows"
BH_ANDROID_CMD_VER="7583922"

function bh_win_install_adb() {
  bh_log_func

  # create opt
  local opt_dst="$BH_OPT"
  bh_test_and_create_dir $opt_dst
  bh_test_and_create_dir $android_sdk_dir

  # android cmd and sdk
  local android_sdk_dir="$opt_dst/android"
  local android_plattools_dir="$android_sdk_dir/platform-tools"
  local android_plattools_url="https://dl.google.com/android/repository/platform-tools_r${BH_PLATOOLS_VER}.zip"
  if ! test -d $android_plattools_dir; then
    bh_decompress_from_url $android_plattools_url $android_sdk_dir
    if test $? != 0; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
  fi
  bh_win_path_add $(winpath $android_plattools_dir)
}

function bh_win_install_flutter() {
  bh_log_func

  # create opt
  local opt_dst="$BH_OPT"
  bh_test_and_create_dir $opt_dst
  bh_test_and_create_dir $android_sdk_dir

  # android cmd and sdk
  local android_sdk_dir="$opt_dst/android"
  local android_cmd_dir="$android_sdk_dir/cmdline-tools"
  local android_cmd_url="https://dl.google.com/android/repository/commandlinetools-win-${BH_ANDROID_CMD_VER}_latest.zip"
  if ! test -d $android_cmd_dir; then
    bh_decompress_from_url $android_cmd_url $android_sdk_dir
    if test $? != 0; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
    bh_win_path_add $(winpath $android_cmd_dir/bin)
  fi
  if ! test -d $android_sdk_dir/platforms; then
    $android_cmd_dir/bin/sdkmanager.bat --sdk_root="$android_sdk_dir" --install 'platform-tools' 'platforms;android-29'
    yes | $android_cmd_dir/bin/sdkmanager.bat --sdk_root="$android_sdk_dir" --licenses
  fi
  bh_win_env_add ANDROID_HOME $(winpath $android_sdk_dir)
  bh_win_env_add ANDROID_SDK_ROOT $(winpath $android_sdk_dir)
  bh_win_path_add $(winpath $android_sdk_dir/platform-tools)

  # flutter
  local flutter_sdk_dir="$opt_dst/flutter"
  local flutter_sdk_url="https://storage.googleapis.com/flutter_infra_release/releases/stable/windows/flutter_windows_${BH_FLUTTER_VER}-stable.zip"
  if ! test -d $flutter_sdk_dir; then
    # opt_dst beacuase zip extract the flutter dir
    bh_decompress_from_url $flutter_sdk_url $opt_dst
    if test $? != 0; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
  fi
  bh_win_path_add $(winpath $flutter_sdk_dir/bin)
}

function bh_win_install_winget() {
  ps_call '
    if (!(Get-Command 'winget.exe' -ea 0)) {
    $repoName = "microsoft/winget-cli"
    $releasesUri = "https://api.github.com/repos/$repoName/releases/latest"
    $url = (Invoke-WebRequest $releasesUri | ConvertFrom-Json).assets | Where-Object name -like *.msixbundle | Select-Object -ExpandProperty browser_download_url
    Invoke-WebRequest $url -OutFile "${env:tmp}\tmp.msixbundle"
    Add-AppPackage -path "${env:tmp}\tmp.msixbundle"
    }
  '
}

function bh_win_install_tesseract() {
  bh_log_func
  if ! type tesseract.exe &>/dev/null; then
    bh_win_get_install tesseract
    bh_win_path_add 'C:\Program Files\Tesseract-OCR'
  fi
}

function bh_win_install_java() {
  bh_log_func
  if ! type java.exe &>/dev/null; then
    bh_win_get_install ojdkbuild.ojdkbuild
    local javahome=$(ps_call '$(get-command java).Source.replace("\bin\java.exe", "")')
    bh_env_add "JAVA_HOME" "$javahome"
  fi
}

function bh_win_install_gsudo() {
  bh_win_get_install gsudo
}

function bh_win_install_wsl() {
  ps_call_script_admin $(unixpath -w $BH_DIR/lib/ps1//install-wsl.ps1)
}

function bh_win_install_docker() {
  bh_log_func
  ps_call_admin Enable-WindowsOptionalFeature -Online -FeatureName $("Microsoft-Hyper-V") -All
  ps_call_admin Enable-WindowsOptionalFeature -Online -FeatureName $("Containers") -All
  bh_win_get_install Docker.DockerDesktop
}

function bh_win_install_choco() {
  bh_log_func
  ps_call_admin '
    if (!(Get-Command "choco.exe" -ea 0)) {
      Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString("https://community.chocolatey.org/install.ps1"))
      choco feature disable -n checksumFiles
      choco feature disable -n showDownloadProgress
      choco feature disable -n showNonElevatedWarnings
      choco feature disable -n logValidationResultsOnWarnings
      choco feature disable -n logEnvironmentValues
      choco feature disable -n exitOnRebootDetected
      choco feature enable -n stopOnFirstPackageFailure
      choco feature enable -n skipPackageUpgradesWhenNotInstalled
      choco feature enable -n logWithoutColor
      choco feature enable -n allowEmptyChecksumsSecure
      choco feature enable -n allowGlobalConfirmation
      choco feature enable -n failOnAutoUninstaller
      choco feature enable -n removePackageInformationOnUninstall
      choco feature enable -n useRememberedArgumentsForUpgrades
    }
  '
}

# ---------------------------------------
# winget
# ---------------------------------------

function bh_win_get_list_installed() {
  winget list
}

function bh_win_get_list_installed_exported_str() {
  powershell -c '
    $tmpfile = New-TemporaryFile
    winget export $tmpfile | Select-String -Pattern "\n|Installed package is not available" -NotMatch
    $pkgs = ((Get-Content $tmpfile | ConvertFrom-Json).Sources.Packages | ForEach-Object { $_.PackageIdentifier }) -join " "
    echo $pkgs
  '
}

function bh_win_get_install() {
  bh_log_func
  local pkgs_to_install=""
  for i in "$@"; do
    if [[ $(winget list --id $i) =~ "No installed"* ]]; then
      pkgs_to_install="$i $pkgs_to_install"
    fi
  done
  if test ! -z "$pkgs_to_install"; then
    echo "pkgs_to_install=$pkgs_to_install"
    for pkg in $pkgs_to_install; do
      winget install $WINGET_ARGS_INSTALL $pkg
    done
  fi
}

function bh_win_get_settings() {
  winget settings
}

function bh_win_get_upgrade() {
  winget upgrade --all --silent
}

# ---------------------------------------
# choco
# ---------------------------------------

function bh_win_choco_list_installed() {
  choco list -l
}

function bh_win_choco_list_installed_str() {
  powershell -c '
      $pkgs = $(choco list -l | ForEach-Object { $_.split(' ')[0] }) -join (" ")
      echo $pkgs
    '
}

function bh_win_choco_install() {
  bh_log_func
  local pkgs_to_install=""
  local pkgs_installed=$(bh_win_choco_list_installed_str)
  for i in "$@"; do
    if [[ ! $pkgs_installed =~ $i ]]; then
      pkgs_to_install="$i $pkgs_to_install"
    fi
  done
  if test ! -z "$pkgs_to_install"; then
    bh_log_msg "pkgs_to_install=$pkgs_to_install"
    for pkg in $pkgs_to_install; do
      gsudo choco install -y --acceptlicense $pkg
    done
  fi
}

function bh_win_choco_uninstall() {
  bh_log_func
  local pkgs_to_uninstall=$(echo $@ | tr ' ' ';')
  gsudo choco uninstall -y --acceptlicense $pkgs_to_uninstall
}

function bh_win_choco_upgrade() {
  bh_log_func
  local outdated=false
  gsudo choco outdated | grep '0 package' >/dev/null || outdated=true
  if $outdated; then gsudo choco upgrade -y --acceptlicense all; fi
}

function bh_win_choco_clean() {
  bh_log_func
  if ! type choco-cleaner.exe &>/dev/null; then
    bh_win_choco_install choco-cleaner
  fi
  ps_call_admin 'Invoke-Expression "$env:ChocolateyToolsLocation\BCURRAN3\choco-cleaner.ps1" | Out-Null'
}

# ---------------------------------------
# open
# ---------------------------------------

function bh_win_open_trash() {
  ps_call 'Start-Process explorer shell:recyclebinfolder'
}

function bh_win_open_appdata_local_programns() {
  ps_call 'Start-Process explorer "${env:localappdata}\Programs"'
}

function bh_win_open_appdata() {
  ps_call 'Start-Process explorer "${env:appdata}"'
}

function bh_win_open_tmp() {
  ps_call 'Start-Process explorer "${env:localappdata}\temp"'
}

function bh_win_open_start_menu_dir() {
  ps_call 'Start-Process explorer "${env:appdata}\Microsoft\Windows\Start Menu\Programs"'
}

function bh_win_open_start_menu_dir_allusers() {
  ps_call 'Start-Process explorer "${env:allusersprofile}\Microsoft\Windows\Start Menu\Programs"'
}

# ---------------------------------------
# explorer
# ---------------------------------------

function bh_win_explorer_restart() {
  ps_call 'taskkill /f /im explorer.exe | Out-Null'
  ps_call 'Start-Process explorer.exe'
}

function bh_win_explorer_home_restore_desktop() {
  ps_call '
    if (Test-Path "${env:userprofile}\Desktop") { return}
    mkdir "${env:userprofile}\Desktop"
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Desktop" /t REG_SZ /d "${env:userprofile}\Desktop" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Desktop" /t REG_EXPAND_SZ /d "${env:userprofile}\Desktop" /f
    attrib +r -s -h "${env:userprofile}\Desktop"
  '
}

function bh_win_explorer_hide_home_dotfiles() {
  bh_log_func
  powershell.exe -c 'Get-ChildItem "${env:userprofile}\.*" | ForEach-Object { $_.Attributes += "Hidden" }'
}

# ---------------------------------------
# sanity
# ---------------------------------------

function bh_win_sanity_ui() {
  ps_call_script $(unixpath -w $BH_DIR/lib/ps1/sanity-ui.ps1)
}

function bh_win_sanity_ctx_menu() {
  ps_call_script_admin $(unixpath -w $BH_DIR/lib/ps1/sanity-cxt-menu.ps1)
}

function bh_win_sanity_services() {
  ps_call_script_admin $(unixpath -w $BH_DIR/lib/ps1/sanity-services.ps1)
}

function bh_win_sanity_password_policy() {
  ps_call_script_admin $(unixpath -w $BH_DIR/lib/ps1/sanity-password-policy.ps1)
}

function bh_win_sanity_this_pc() {
  ps_call_script_admin $(unixpath -w $BH_DIR/lib/ps1/sanity-this-pc.ps1)
}

function bh_win_sanity_all() {
  bh_win_sanity_ui
  bh_win_sanity_ctx_menu
  bh_win_sanity_this_pc
  bh_win_sanity_password_policy
  bh_win_sanity_services
}
