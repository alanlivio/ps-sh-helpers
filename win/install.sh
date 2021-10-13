# ---------------------------------------
# install non-admin
# ---------------------------------------

function bh_install_win_python() {
  winget install -i Python.Python.3 --version 3.9.7150.0 --source winget
}

function bh_install_win_zotero() {
  winget install -i Zotero.Zotero
}

function bh_install_win_vscode() {
  winget install -i Microsoft.VisualStudioCode
}

function bh_install_win_miktex() {
  winget install -i MiKTeX
}

function bh_install_win_make() {
  local url="https://jztkft.dl.sourceforge.net/project/ezwinports/make-4.3-without-guile-w32-bin.zip"
  local bin_dir="$BH_OPT_WIN/make-4.3-without-guile-w32-bin"
  if ! test -d $bin_dir; then
    bh_test_and_create_folder $bin_dir
    bh_decompress_from_url $url $bin_dir # no root folder
    if test $? != 0; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
    bh_path_win_add $(winpath $bin_dir/bin)
  fi
}

BH_FFMPEG_VER="4.4"
function bh_install_win_ffmpeg() {
  local url="https://www.gyan.dev/ffmpeg/builds/packages/ffmpeg-${BH_FFMPEG_VER}-essentials_build.zip"
  local bin_dir="$BH_OPT_WIN/ffmpeg-${BH_FFMPEG_VER}-essentials_build/bin/"
  if ! test -d $bin_dir; then
    bh_decompress_from_url $url $BH_OPT_WIN/ # has root folder
    if [[ $? != 0 || ! -d $bin_dir ]]; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
    bh_path_win_add $(winpath $bin_dir)
  fi
}

BH_NODE_VER="14.17.5"
function bh_install_win_node() {
  local url="https://nodejs.org/dist/v${BH_NODE_VER}/node-v${BH_NODE_VER}-win-x64.zip"
  local bin_dir="$BH_OPT_WIN/node-v${BH_NODE_VER}-win-x64"
  if ! test -d $bin_dir; then
    bh_test_and_create_folder $bin_dir # no root folder
    bh_decompress_from_url $url $BH_OPT_WIN
    if test $? != 0; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
    bh_env_win_add 'NODEJS_HOME' $(winpath $bin_dir)
    bh_path_win_add $(winpath $bin_dir)
  fi
}

BH_FLUTTER_VER="2.2.3"
BH_ANDROID_CMD_VER="7583922"
function bh_install_win_androidcmd_flutter() {
  bh_log_func

  # create opt
  local opt_dst="$BH_OPT_WIN"
  bh_test_and_create_folder $opt_dst

  # android cmd and sdk
  local android_sdk_dir="$opt_dst/android"
  local android_cmd_dir="$android_sdk_dir/cmdline-tools"
  local android_cmd_url="https://dl.google.com/android/repository/commandlinetools-win-${BH_ANDROID_CMD_VER}_latest.zip"
  if ! test -d $android_cmd_dir; then
    bh_decompress_from_url $android_cmd_url $android_sdk_dir
    if test $? != 0; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
    bh_path_win_add $(winpath $android_cmd_dir/bin)
  fi
  if ! test -d $android_sdk_dir/platforms; then
    $android_cmd_dir/bin/sdkmanager.bat --sdk_root="$android_sdk_dir" --install 'platform-tools' 'platforms;android-29'
    yes | $android_cmd_dir/bin/sdkmanager.bat --sdk_root="$android_sdk_dir" --licenses
    bh_env_win_add ANDROID_HOME $(winpath $android_sdk_dir)
    bh_env_win_add ANDROID_SDK_ROOT $(winpath $android_sdk_dir)
    bh_path_win_add $(winpath $android_sdk_dir/platform-tools)
  fi

  # flutter
  local flutter_sdk_dir="$opt_dst/flutter"
  local flutter_sdk_url="https://storage.googleapis.com/flutter_infra_release/releases/stable/windows/flutter_windows_${BH_FLUTTER_VER}-stable.zip"
  if ! test -d $flutter_sdk_dir; then
    # opt_dst beacuase zip extract the flutter dir
    bh_decompress_from_url $flutter_sdk_url $opt_dst
    if test $? != 0; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
    bh_path_win_add $(winpath $flutter_sdk_dir/bin)
  fi
}

function bh_install_win_latexindent() {
  bh_log_func
  if ! type latexindent.exe &>/dev/null; then
    bh_curl_fetch_to_dir https://github.com/cmhughes/latexindent.pl/releases/download/V3.10/latexindent.exe $BH_OPT_WIN
    bh_curl_fetch_to_dir https://raw.githubusercontent.com/cmhughes/latexindent.pl/main/defaultSettings.yaml $BH_OPT_WIN
    bh_path_win_add $BH_OPT_WIN
  fi
}
