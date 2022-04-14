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
function open { ps_call "Start-Process ${1:-.}"; }
if type gsudo &>/dev/null; then HAS_GSUDO=true; else HAS_GSUDO=false; fi

# ---------------------------------------
# gitbash
# ---------------------------------------

function win_gitbash_fix_prompt {
  log_func
  sed 's/show\sMSYSTEM/#&/g' -i /etc/profile.d/git-prompt.sh
  sed "s/PS1=\"\$PS1\"'\\\\n/#&/g" -i /etc/profile.d/git-prompt.sh
}

function win_gitbash_open_prompt {
  log_func
  open "$(winpath /etc/profile.d/git-prompt.sh)"
}

# ---------------------------------------
# recycle_bin
# ---------------------------------------

function win_recycle_bin_clean() {
  log_func
  ps_call 'Clear-RecycleBin -Confirm:$false 2> $null'
}

# ---------------------------------------
# sound
# ---------------------------------------

function win_sound_open_settings() {
  rundll32.exe shell32.dll,control_rundll mmsys.cpl,,2
}

# ---------------------------------------
# wt
# ---------------------------------------

function win_wt_open_settings() {
  wt_stgs="$HOME/AppData/Local/Packages/Microsoft.WindowsTerminal_8wekyb3d8bbwe/LocalState/settings.json"
  code $wt_stgs
}

# ---------------------------------------
# user
# ---------------------------------------

function win_user_check_admin_group() {
  # usage if [ "$(win_user_check_admin_group)" == "True" ]; then <commands>; fi
  ps_call '
    $user = "$env:COMPUTERNAME\$env:USERNAME"
    $group = "Administrators"
    (Get-LocalGroupMember $group).Name -contains $user
  '
}

function win_user_check_eleveated_shell() {
  ps_call '(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)' | tr -d '\rn'
}

function win_user_adminstrator_enable() {
  ps_call_admin 'net user administrator /active:yes'
}

function win_user_adminstrator_disable() {
  ps_call_admin 'net user administrator /active:no'
}

# ---------------------------------------
# sysupdate
# ---------------------------------------

function win_sysupdate_win() {
  log_func
  ps_call_admin '
    Install-Module -Name PSWindowsUpdate -Force
    $(Install-WindowsUpdate -AcceptAll -IgnoreReboot) | Where-Object { 
    if ($_ -is [string]) {
      $_.Split("", [System.StringSplitOptions]::RemoveEmptyEntries) 
    } 
  }'
}

function win_sysupdate_win_list() {
  ps_call_admin 'Get-WindowsUpdate'
}

function win_sysupdate_win_list_last_installed() {
  ps_call_admin 'Get-WUHistory -Last 10 | Select-Object Date, Title, Result'
}

# ---------------------------------------
# feature
# ---------------------------------------

function win_feature_enable_ssh_server_bash() {
  log_func
  local current_bash_path=$(where bash | head -1)
  ps_call_admin "
    Add-WindowsCapability -Online -Name OpenSSH.Client
    Add-WindowsCapability -Online -Name OpenSSH.Server
    Start-Service sshd
    Set-Service -Name sshd -StartupType 'Automatic'
    New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value '$current_bash_path' -PropertyType String -Force
  "
}

function win_feature_list_enabled() {
  log_msg "WindowsOptionalFeatures"
  ps_call_admin 'Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Enabled"}'
  log_msg "WindowsCapabilities"
  ps_call_admin 'Get-WindowsCapability -Online | Where-Object {$_.State -eq "Installed"}'
}

function win_feature_list_disabled() {
  log_msg "WindowsOptionalFeatures"
  ps_call_admin 'Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Disabled"}'
  log_msg "WindowsCapabilities"
  ps_call_admin 'Get-WindowsCapability -Online | Where-Object {$_.State -eq "NotPresent"}'
}

# ---------------------------------------
# appx
# ---------------------------------------

function win_appx_list_installed() {
  ps_call_admin "Get-AppxPackage -AllUsers | Select-Object Name, PackageFullName"
}

function win_appx_uninstall() {
  ps_call_admin '
  if (Get-AppxPackage -Name ' "$1" ') {
    Get-AppxPackage' "$1" '| Remove-AppxPackage
  }
  '
}

function win_appx_install() {
  ps_call_admin '
    Get-AppxPackage ' "$1" '| ForEach-Object { Add-AppxPackage -ea 0 -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" } | Out-null
  '
}

# ---------------------------------------
# services
# ---------------------------------------

function win_services_list_running() {
  ps_call_admin 'Get-Service | Where-Object {$_.Status -eq "Running"}'
}

# ---------------------------------------
# env
# ---------------------------------------

function win_env_show() {
  ps_call 'Get-ChildItem Env:'
}

function win_env_add() {
  : ${2?"Usage: ${FUNCNAME[0]} <varname> <value>"}
  ps_call "[System.Environment]::SetEnvironmentVariable('$1', '$2', 'user')"
}

# ---------------------------------------
# path
# ---------------------------------------

function win_path_show() {
  ps_call '(Get-ChildItem Env:Path).Value'
}

function win_path_show_as_list() {
  IFS=';' read -ra ADDR <<<$(win_path_show)
  for i in "${!ADDR[@]}"; do echo ${ADDR[$i]}; done
}

function win_path_add() {
  local dir=$(winpath $@)
  ps_call ' 
    function win_path_add($addDir) {
      $currentpath = [System.Environment]::GetEnvironmentVariable("PATH", "user")
      $regexAddPath = [regex]::Escape($addDir)
      $arrPath = $currentpath -split ";" | Sort-Object -Unique | Where-Object { $_ -notMatch "^$regexAddPath\\?" }
      $newpath = ($arrPath + $addDir) -join ";"
      [System.Environment]::SetEnvironmentVariable("PATH", $newpath, "user")
    }; win_path_add ' \"$dir\"
}

function win_path_remove() {
  local dir=$(winpath $@)
  ps_call ' 
    function win_path_remove($remDir) {
      $currentpath = [System.Environment]::GetEnvironmentVariable("PATH", "user")
      $newpath = ($currentpath.Split(";") | Where-Object { $_ -ne "$remDir" }) -join ";"
      [System.Environment]::SetEnvironmentVariable("PATH", $newpath, "user")
    }; win_path_remove ' \"$dir\"
}

function win_path_add_winapps() {
  win_path_add "$HOME/AppData/Local/Microsoft/WindowsApps/"
}

function win_path_open_settings() {
  rundll32 sysdm.cpl,EditEnvironmentVariables &
}

# ---------------------------------------
# install
# ---------------------------------------

function win_install_store_essentials() {
  local pkgs='Microsoft.WindowsStore Microsoft.WindowsCalculator Microsoft.Windows.Photos Microsoft.WindowsFeedbackHub Microsoft.WindowsCamera Microsoft.WindowsSoundRecorder'
  for pkg in $pkgs; do
    ps_call "
      Get-AppxPackage $pkg | ForEach-Object { Add-AppxPackage -ea 0 -DisableDevelopmentMode -Register \"\$(\$_.InstallLocation)\AppXManifest.xml\" } | Out-null
    "
  done
}

function win_install_python() {
  winget install Python.Python.3 --source winget -i
  win_path_add $(winpath $HOME/AppData/Local/Programs/Python/Python310/Scripts/)
  win_path_add $(winpath $HOME/AppData/Roaming/Python/Python310/Scripts/)
}

function win_install_miktex() {
  win_get_install ChristianSchenk.MiKTeX
  win_path_add $(winpath $HOME/AppData/Local/Programs/MiKTeX/miktex/bin/x64/)
}

function win_install_gitforwindows_and_wt() {
  ps_call_script $(unixpath -w $BH_DIR/lib/ps1/install-gitforwindows-and-wt.ps1)
}

function win_install_msys() {
  ps_call_script $(unixpath -w $BH_DIR/lib/ps1/install-msys.ps1)
}

function win_install_ghostscript() {
  win_get_install ArtifexSoftware.GhostScript
  win_path_add $(winpath '/c/Program Files/gs/gs9.55.0/bin')
}

function win_install_vscode() {
  win_get_install Microsoft.VisualStudioCode
}

function win_install_cmake() {
  win_get_install Kitware.CMake
}

function win_install_pgrep() {
  local url="https://soft.rubypdf.com/download/pdfgrep/pdfgrep-1.4.0-win32.zip"
  local bin_dir="$BH_OPT/pdfgrep"
  if ! test -f $bin_dir; then
    decompress_from_url $url $bin_dir
    if test $? != 0; then log_error "decompress_from_url failed." && return 1; fi
  fi
  win_path_add $(winpath $bin_dir)
}

function win_install_make() {
  local url="https://jztkft.dl.sourceforge.net/project/ezwinports/make-4.3-without-guile-w32-bin.zip"
  local bin_dir="$BH_OPT/make-4.3-without-guile-w32-bin"
  if ! test -d $bin_dir; then
    test_and_create_dir $bin_dir
    decompress_from_url $url $bin_dir # no root dir
    if test $? != 0; then log_error "decompress_from_url failed." && return 1; fi
  fi
  win_path_add $(winpath $bin_dir/bin)
}

BH_FFMPEG_VER="4.4"
function win_install_ffmpeg() {
  local url="https://www.gyan.dev/ffmpeg/builds/packages/ffmpeg-${BH_FFMPEG_VER}-essentials_build.zip"
  local bin_dir="$BH_OPT/ffmpeg-${BH_FFMPEG_VER}-essentials_build/bin/"
  if ! test -d $bin_dir; then
    decompress_from_url $url $BH_OPT/ # has root dir
    if [[ $? != 0 || ! -d $bin_dir ]]; then log_error "decompress_from_url failed." && return 1; fi
  fi
  win_path_add $(winpath $bin_dir)
}

BH_NODE_VER="14.17.5"
function win_install_node() {
  local url="https://nodejs.org/dist/v${BH_NODE_VER}/node-v${BH_NODE_VER}-win-x64.zip"
  local bin_dir="$BH_OPT/node-v${BH_NODE_VER}-win-x64"
  if ! test -d $bin_dir; then
    test_and_create_dir $bin_dir # no root dir
    decompress_from_url $url $BH_OPT
    if test $? != 0; then log_error "decompress_from_url failed." && return 1; fi
  fi
  win_env_add 'NODEJS_HOME' $(winpath $bin_dir)
  win_path_add $(winpath $bin_dir)
}

BH_FLUTTER_VER="2.2.3"
BH_PLATOOLS_VER="31.0.3-windows"
BH_ANDROID_CMD_VER="7583922"

function win_install_adb() {
  log_func

  # create opt
  local opt_dst="$BH_OPT"
  test_and_create_dir $opt_dst
  test_and_create_dir $android_sdk_dir

  # android cmd and sdk
  local android_sdk_dir="$opt_dst/android"
  local android_plattools_dir="$android_sdk_dir/platform-tools"
  local android_plattools_url="https://dl.google.com/android/repository/platform-tools_r${BH_PLATOOLS_VER}.zip"
  if ! test -d $android_plattools_dir; then
    decompress_from_url $android_plattools_url $android_sdk_dir
    if test $? != 0; then log_error "decompress_from_url failed." && return 1; fi
  fi
  win_path_add $(winpath $android_plattools_dir)
}

function win_install_flutter() {
  log_func

  # create opt
  local opt_dst="$BH_OPT"
  test_and_create_dir $opt_dst
  test_and_create_dir $android_sdk_dir

  # android cmd and sdk
  local android_sdk_dir="$opt_dst/android"
  local android_cmd_dir="$android_sdk_dir/cmdline-tools"
  local android_cmd_url="https://dl.google.com/android/repository/commandlinetools-win-${BH_ANDROID_CMD_VER}_latest.zip"
  if ! test -d $android_cmd_dir; then
    decompress_from_url $android_cmd_url $android_sdk_dir
    if test $? != 0; then log_error "decompress_from_url failed." && return 1; fi
    win_path_add $(winpath $android_cmd_dir/bin)
  fi
  if ! test -d $android_sdk_dir/platforms; then
    $android_cmd_dir/bin/sdkmanager.bat --sdk_root="$android_sdk_dir" --install 'platform-tools' 'platforms;android-29'
    yes | $android_cmd_dir/bin/sdkmanager.bat --sdk_root="$android_sdk_dir" --licenses
  fi
  win_env_add ANDROID_HOME $(winpath $android_sdk_dir)
  win_env_add ANDROID_SDK_ROOT $(winpath $android_sdk_dir)
  win_path_add $(winpath $android_sdk_dir/platform-tools)

  # flutter
  local flutter_sdk_dir="$opt_dst/flutter"
  local flutter_sdk_url="https://storage.googleapis.com/flutter_infra_release/releases/stable/windows/flutter_windows_${BH_FLUTTER_VER}-stable.zip"
  if ! test -d $flutter_sdk_dir; then
    # opt_dst beacuase zip extract the flutter dir
    decompress_from_url $flutter_sdk_url $opt_dst
    if test $? != 0; then log_error "decompress_from_url failed." && return 1; fi
  fi
  win_path_add $(winpath $flutter_sdk_dir/bin)
}

function win_install_winget() {
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

function win_install_tesseract() {
  log_func
  if ! type tesseract.exe &>/dev/null; then
    win_get_install tesseract
    win_path_add 'C:\Program Files\Tesseract-OCR'
  fi
}

function win_install_java() {
  log_func
  if ! type java.exe &>/dev/null; then
    win_get_install ojdkbuild.ojdkbuild
    local javahome=$(ps_call '$(get-command java).Source.replace("\bin\java.exe", "")')
    env_add "JAVA_HOME" "$javahome"
  fi
}

function win_install_gsudo() {
  win_get_install gsudo
}

function win_install_wsl() {
  ps_call_script_admin $(unixpath -w $BH_DIR/lib/ps1/install-wsl.ps1)
}

function win_install_docker() {
  log_func
  ps_call_admin Enable-WindowsOptionalFeature -Online -FeatureName $("Microsoft-Hyper-V") -All
  ps_call_admin Enable-WindowsOptionalFeature -Online -FeatureName $("Containers") -All
  win_get_install Docker.DockerDesktop
}

function win_install_choco() {
  log_func
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

function win_get_list_installed() {
  winget list
}

function win_get_list_installed_exported_str() {
  powershell -c '
    $tmpfile = New-TemporaryFile
    winget export $tmpfile | Select-String -Pattern "\n|Installed package is not available" -NotMatch
    $pkgs = ((Get-Content $tmpfile | ConvertFrom-Json).Sources.Packages | ForEach-Object { $_.PackageIdentifier }) -join " "
    echo $pkgs
  '
}

function win_get_install() {
  log_func
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

function win_get_settings() {
  winget settings
}

function win_get_upgrade() {
  winget upgrade --all --silent
}

# ---------------------------------------
# open
# ---------------------------------------

function win_open_trash() {
  ps_call 'Start-Process explorer shell:recyclebinfolder'
}

function win_open_appdata_local_programns() {
  ps_call 'Start-Process explorer "${env:localappdata}\Programs"'
}

function win_open_appdata() {
  ps_call 'Start-Process explorer "${env:appdata}"'
}

function win_open_tmp() {
  ps_call 'Start-Process explorer "${env:localappdata}\temp"'
}

function win_open_start_menu_dir() {
  ps_call 'Start-Process explorer "${env:appdata}\Microsoft\Windows\Start Menu\Programs"'
}

function win_open_start_menu_dir_allusers() {
  ps_call 'Start-Process explorer "${env:allusersprofile}\Microsoft\Windows\Start Menu\Programs"'
}

# ---------------------------------------
# explorer
# ---------------------------------------

function win_explorer_restart() {
  ps_call 'taskkill /f /im explorer.exe | Out-Null'
  ps_call 'Start-Process explorer.exe'
}

function win_explorer_home_restore_desktop() {
  ps_call '
    if (Test-Path "${env:userprofile}\Desktop") { return}
    mkdir "${env:userprofile}\Desktop"
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Desktop" /t REG_SZ /d "${env:userprofile}\Desktop" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Desktop" /t REG_EXPAND_SZ /d "${env:userprofile}\Desktop" /f
    attrib +r -s -h "${env:userprofile}\Desktop"
  '
}

function win_explorer_hide_home_dotfiles() {
  log_func
  powershell.exe -c 'Get-ChildItem "${env:userprofile}\.*" | ForEach-Object { $_.Attributes += "Hidden" }'
}

# ---------------------------------------
# sanity
# ---------------------------------------

function win_sanity_ui() {
  ps_call_script $(unixpath -w $BH_DIR/lib/ps1/sanity-ui.ps1)
}

function win_sanity_ctx_menu() {
  ps_call_script_admin $(unixpath -w $BH_DIR/lib/ps1/sanity-cxt-menu.ps1)
}

function win_sanity_services() {
  ps_call_script_admin $(unixpath -w $BH_DIR/lib/ps1/sanity-services.ps1)
}

function win_sanity_password_policy() {
  ps_call_script_admin $(unixpath -w $BH_DIR/lib/ps1/sanity-password-policy.ps1)
}

function win_sanity_this_pc() {
  ps_call_script_admin $(unixpath -w $BH_DIR/lib/ps1/sanity-this-pc.ps1)
}

function win_sanity_all() {
  win_sanity_ui
  win_sanity_ctx_menu
  win_sanity_this_pc
  win_sanity_password_policy
  win_sanity_services
}
