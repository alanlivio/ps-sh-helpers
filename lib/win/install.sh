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
}

function bh_win_install_miktex() {
  bh_win_get_install ChristianSchenk.MiKTeX
  bh_win_path_add $(winpath $HOME/AppData/Local/Programs/MiKTeX/miktex/bin/x64/)
}

function bh_win_install_zotero() {
  bh_win_get_install Zotero.Zotero
}

function bh_win_install_gitforwindows() {
  ps_call_script $(unixpath -w $BH_DIR/lib/win/install-gitforwindows.ps1)
}

function bh_win_install_msys() {
  ps_call_script $(unixpath -w $BH_DIR/lib/win/install-msys.ps1)
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

function bh_win_install_make() {
  local url="https://jztkft.dl.sourceforge.net/project/ezwinports/make-4.3-without-guile-w32-bin.zip"
  local bin_dir="$BH_OPT_WIN/make-4.3-without-guile-w32-bin"
  if ! test -d $bin_dir; then
    bh_test_and_create_folder $bin_dir
    bh_decompress_from_url $url $bin_dir # no root folder
    if test $? != 0; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
  fi
  bh_win_path_add $(winpath $bin_dir/bin)
}

BH_FFMPEG_VER="4.4"
function bh_win_install_ffmpeg() {
  local url="https://www.gyan.dev/ffmpeg/builds/packages/ffmpeg-${BH_FFMPEG_VER}-essentials_build.zip"
  local bin_dir="$BH_OPT_WIN/ffmpeg-${BH_FFMPEG_VER}-essentials_build/bin/"
  if ! test -d $bin_dir; then
    bh_decompress_from_url $url $BH_OPT_WIN/ # has root folder
    if [[ $? != 0 || ! -d $bin_dir ]]; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
  fi
  bh_win_path_add $(winpath $bin_dir)
}

BH_NODE_VER="14.17.5"
function bh_win_install_node() {
  local url="https://nodejs.org/dist/v${BH_NODE_VER}/node-v${BH_NODE_VER}-win-x64.zip"
  local bin_dir="$BH_OPT_WIN/node-v${BH_NODE_VER}-win-x64"
  if ! test -d $bin_dir; then
    bh_test_and_create_folder $bin_dir # no root folder
    bh_decompress_from_url $url $BH_OPT_WIN
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
  local opt_dst="$BH_OPT_WIN"
  bh_test_and_create_folder $opt_dst
  bh_test_and_create_folder $android_sdk_dir

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
  local opt_dst="$BH_OPT_WIN"
  bh_test_and_create_folder $opt_dst
  bh_test_and_create_folder $android_sdk_dir

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

function bh_win_install_latexindent() {
  bh_log_func
  if ! type latexindent.exe &>/dev/null; then
    bh_curl_fetch_to_dir https://github.com/cmhughes/latexindent.pl/releases/download/V3.10/latexindent.exe $BH_OPT_WIN
    bh_curl_fetch_to_dir https://raw.githubusercontent.com/cmhughes/latexindent.pl/main/defaultSettings.yaml $BH_OPT_WIN
    bh_win_path_add $BH_OPT_WIN
  fi
}

function bh_win_install_winget() {
  ps_call '
    if (!(Get-Command 'winget.exe' -ea 0)) {
      Invoke-Expression $bh_log_func
      Get-AppxPackage Microsoft.DesktopAppInstaller | ForEach-Object { Add-AppxPackage -ea 0 -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" } | Out-null
    }
  '
}

function bh_win_install_winget_from_github() {
  ps_call '
    if (!(Get-Command 'winget.exe' -ea 0)) {
      Invoke-WebRequest -URI https://github.com/microsoft/winget-cli/releases/download/v1.0.11692/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle -UseBasicParsing -OutFile $env:TEMP\tmp.msixbundle
      Add-AppxPackage -Path $env:TEMP\tmp.msixbundle
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
  ps_call_script_admin $(unixpath -w $BH_DIR/lib/win//install-wsl.ps1)
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
