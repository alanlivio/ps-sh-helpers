alias ls='ls --color=auto --hide=ntuser* --hide=NTUSER* --hide=AppData --hide=IntelGraphicsProfiles* --hide=MicrosoftEdgeBackups'

function win_trash_clean() {
  powershell -c 'Clear-RecycleBin -Confirm:$false 2> $null'
}

function win_trash_open() {
  powershell -c 'Start-Process explorer shell:recyclebinfolder'
}

function explorer_restart() {
  powershell -c 'taskkill /f /im explorer | Out-Null; Start-Process explorer'
}

function explorer_tmp() {
  powershell -c 'Start-Process explorer "${env:localappdata}\\temp\'
}

function explorer_hide_home_dotfiles() {
  powershell -c 'Get-ChildItem "${env:userprofile}\\.*" | ForEach-Object { $_.Attributes += "Hidden" }'
}

function win_user_is_admin() {
  # return True/False
  powershell -c ' (Get-LocalGroupMember "Administrators").Name -contains "$env:COMPUTERNAME\$env:USERNAME" '
}

function win_shell_eleveated() {
  powershell -c '(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)' # return True/False
}

# ---------------------------------------
# msys
# ---------------------------------------

function msys_fix_home() {
  if ! test -d /mnt/; then mkdir /mnt/; fi
  echo -e "none / cygdrive binary,posix=0,noacl,user 0 0" | tee /etc/fstab
  echo -e "C:/Users /home ntfs binary,noacl,auto 1 1" | tee -a /etc/fstab
  echo -e "C:/Users /Users ntfs binary,noacl,auto 1 1" | tee -a /etc/fstab
  # use /mnt/c/ like in WSL
  echo -e "/c /mnt/c none bind" | tee -a /etc/fstab
  echo -e 'db_home: windows >> /etc/nsswitch.conf' | tee -a /etc/nsswitch.conf
}

# ---------------------------------------
# sysupdate
# ---------------------------------------

function win_sysupdate() {
  gsudo powershell -c '
    Install-Module -Name PSWindowsUpdate -Force
    $(Install-WindowsUpdate -AcceptAll -IgnoreReboot) | Where-Object { 
    if ($_ -is [string]) {
      $_.Split("", [System.StringSplitOptions]::RemoveEmptyEntries) 
    } 
  }'
}

function win_sysupdate_list() {
  gsudo powershell -c 'Get-WindowsUpdate'
}

function win_sysupdate_list_last_installed() {
  gsudo powershell -c 'Get-WUHistory -Last 10 | Select-Object Date, Title, Result'
}

# ---------------------------------------
# feature
# ---------------------------------------

function win_feature_enable_ssh_server_bash() {
  local current_bash_path=$(where bash | head -1)
  gsudo powershell -c "
    Add-WindowsCapability -Online -Name OpenSSH.Client
    Add-WindowsCapability -Online -Name OpenSSH.Server
    Start-Service sshd
    Set-Service -Name sshd -StartupType 'Automatic'
    New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value '$current_bash_path' -PropertyType String -Force
  "
}

function win_feature_list_enabled() {
  log_msg "WindowsOptionalFeatures"
  gsudo powershell -c 'Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Enabled"}'
  log_msg "WindowsCapabilities"
  gsudo powershell -c 'Get-WindowsCapability -Online | Where-Object {$_.State -eq "Installed"}'
}

function win_feature_list_disabled() {
  log_msg "WindowsOptionalFeatures"
  gsudo powershell -c 'Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Disabled"}'
  log_msg "WindowsCapabilities"
  gsudo powershell -c 'Get-WindowsCapability -Online | Where-Object {$_.State -eq "NotPresent"}'
}

# ---------------------------------------
# appx
# ---------------------------------------

function win_appx_list_installed() {
  gsudo powershell -c "Get-AppxPackage -AllUsers | Select-Object Name, PackageFullName"
}

function win_appx_uninstall() {
  gsudo powershell -c '
  if (Get-AppxPackage -Name ' "$1" ') {
    Get-AppxPackage' "$1" '| Remove-AppxPackage
  }
  '
}

function win_appx_install() {
  gsudo powershell -c '
    Get-AppxPackage ' "$1" '| ForEach-Object { Add-AppxPackage -ea 0 -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" } | Out-null
  '
}

# ---------------------------------------
# services
# ---------------------------------------

function win_services_list_running() {
  gsudo powershell -c 'Get-Service | Where-Object {$_.Status -eq "Running"}'
}

# ---------------------------------------
# env
# ---------------------------------------

function win_env_show() {
  powershell -c 'Get-ChildItem Env:'
}

function win_env_add() {
  : ${2?"Usage: ${FUNCNAME[0]} <varname> <value>"}
  powershell -c "[System.Environment]::SetEnvironmentVariable('$1', '$2', 'user')"
}

# ---------------------------------------
# path
# ---------------------------------------

function win_path_show() {
  powershell -c '(Get-ChildItem Env:Path).Value'
}

function win_path_show_as_list() {
  IFS=';' read -ra ADDR <<<$(win_path_show)
  for i in "${!ADDR[@]}"; do echo ${ADDR[$i]}; done
}

function win_path_add() {
  local dir=$(cygpath -w $@)
  powershell -c ' 
    function win_path_add($addDir) {
      $currentpath = [System.Environment]::GetEnvironmentVariable("PATH", "user")
      $regexAddPath = [regex]::Escape($addDir)
      $arrPath = $currentpath -split ";" | Sort-Object -Unique | Where-Object { $_ -notMatch "^$regexAddPath\\?" }
      $newpath = ($arrPath + $addDir) -join ";"
      [System.Environment]::SetEnvironmentVariable("PATH", $newpath, "user")
    }; win_path_add ' \"$dir\"
}

function win_path_rm() {
  local dir=$(cygpath -w $@)
  powershell -c ' 
    function win_path_rm($remDir) {
      $currentpath = [System.Environment]::GetEnvironmentVariable("PATH", "user")
      $newpath = ($currentpath.Split(";") | Where-Object { $_ -ne "$remDir" }) -join ";"
      [System.Environment]::SetEnvironmentVariable("PATH", $newpath, "user")
    }; win_path_rm ' \"$dir\"
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

function win_install_gitforwindows_and_wt() {
  powershell -c_script $(cygpath -w $BH_DIR/plugins/ps1/install-gitforwindows-and-wt.ps1)
}

function win_install_msys() {
  powershell -c_script $(cygpath -w $BH_DIR/plugins/ps1/install-msys.ps1)
}

function win_install_ghostscript() {
  win_get_install ArtifexSoftware.GhostScript
  win_path_add $(cygpath -w '/c/Program Files/gs/gs9.55.0/bin')
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
  win_path_add $(cygpath -w $bin_dir)
}

function win_install_make() {
  local url="https://jztkft.dl.sourceforge.net/project/ezwinports/make-4.3-without-guile-w32-bin.zip"
  local bin_dir="$BH_OPT/make-4.3-without-guile-w32-bin"
  if ! test -d $bin_dir; then
    test_and_create_dir $bin_dir
    decompress_from_url $url $bin_dir # no root dir
    if test $? != 0; then log_error "decompress_from_url failed." && return 1; fi
  fi
  win_path_add $(cygpath -w $bin_dir/bin)
}

BH_FFMPEG_VER="4.4"
function win_install_ffmpeg() {
  local url="https://www.gyan.dev/ffmpeg/builds/packages/ffmpeg-${BH_FFMPEG_VER}-essentials_build.zip"
  local bin_dir="$BH_OPT/ffmpeg-${BH_FFMPEG_VER}-essentials_build/bin/"
  if ! test -d $bin_dir; then
    decompress_from_url $url $BH_OPT/ # has root dir
    if [[ $? != 0 || ! -d $bin_dir ]]; then log_error "decompress_from_url failed." && return 1; fi
  fi
  win_path_add $(cygpath -w $bin_dir)
}

BH_NODE_VER="14.17.5"
function win_install_node() {
  winget install OpenJS.NodeJS
}

BH_FLUTTER_VER="2.2.3"
BH_PLATOOLS_VER="31.0.3-windows"
BH_ANDROID_CMD_VER="7583922"

function win_install_adb() {
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
  win_path_add $(cygpath -w $android_plattools_dir)
}

function win_install_flutter() {

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
    win_path_add $(cygpath -w $android_cmd_dir/bin)
  fi
  if ! test -d $android_sdk_dir/platforms; then
    $android_cmd_dir/bin/sdkmanager.bat --sdk_root="$android_sdk_dir" --install 'platform-tools' 'platforms;android-29'
    yes | $android_cmd_dir/bin/sdkmanager.bat --sdk_root="$android_sdk_dir" --licenses
  fi
  win_env_add ANDROID_HOME $(cygpath -w $android_sdk_dir)
  win_env_add ANDROID_SDK_ROOT $(cygpath -w $android_sdk_dir)
  win_path_add $(cygpath -w $android_sdk_dir/platform-tools)

  # flutter
  local flutter_sdk_dir="$opt_dst/flutter"
  local flutter_sdk_url="https://storage.googleapis.com/flutter_infra_release/releases/stable/windows/flutter_windows_${BH_FLUTTER_VER}-stable.zip"
  if ! test -d $flutter_sdk_dir; then
    # opt_dst beacuase zip extract the flutter dir
    decompress_from_url $flutter_sdk_url $opt_dst
    if test $? != 0; then log_error "decompress_from_url failed." && return 1; fi
  fi
  win_path_add $(cygpath -w $flutter_sdk_dir/bin)
}

function win_install_tesseract() {
  if ! type tesseract.exe &>/dev/null; then
    win_get_install tesseract
    win_path_add 'C:\Program Files\Tesseract-OCR'
  fi
}

function win_install_java() {
  if ! type java.exe &>/dev/null; then
    win_get_install ojdkbuild.ojdkbuild
    local javahome=$(powershell -c '$(get-command java).Source.replace("\bin\java.exe", "")')
    env_add "JAVA_HOME" "$javahome"
  fi
}

function win_install_gsudo() {
  win_get_install gsudo
}

function win_install_wsl() {
  gsudo powershell $(cygpath -w $BH_DIR/plugins/ps1/install-wsl.ps1)
}

function win_install_docker() {
  gsudo powershell -c Enable-WindowsOptionalFeature -Online -FeatureName $("Microsoft-Hyper-V") -All
  gsudo powershell -c Enable-WindowsOptionalFeature -Online -FeatureName $("Containers") -All
  win_get_install Docker.DockerDesktop
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
# sanity
# ---------------------------------------

function win_sanity_ui() {
  powershell $(cygpath -w $BH_DIR/plugins/ps1/sanity-ui.ps1)
}

function win_sanity_ctx_menu() {
  gsudo powershell $(cygpath -w $BH_DIR/plugins/ps1/sanity-cxt-menu.ps1)
}

function win_sanity_services() {
  gsudo powershell $(cygpath -w $BH_DIR/plugins/ps1/sanity-services.ps1)
}

function win_sanity_password_policy() {
  gsudo powershell $(cygpath -w $BH_DIR/plugins/ps1/sanity-password-policy.ps1)
}

function win_sanity_this_pc() {
  gsudo powershell $(cygpath -w $BH_DIR/plugins/ps1/sanity-this-pc.ps1)
}

function win_sanity_all() {
  win_sanity_ui
  win_sanity_ctx_menu
  win_sanity_this_pc
  win_sanity_password_policy
  win_sanity_services
}
