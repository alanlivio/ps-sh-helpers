# ---------------------------------------
# install non-admin
# ---------------------------------------

BH_NODE_VER="14.17.5"
function bh_install_win_node() {
  local nvm_url="https://nodejs.org/dist/v${BH_NODE_VER}/node-v${BH_NODE_VER}-win-x64.zip"
  local nodejs_dir="$BH_OPT_WIN/nodejs"
  if ! test -d $nodejs_dir; then
    bh_test_and_create_folder $nodejs_dir
    bh_decompress_from_url $nvm_url $nodejs_dir
    if test $? != 0; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
    bh_win_env_add 'NODEJS_HOME' $(winpath $nodejs_dir)
    bh_win_path_add $(winpath $nodejs_dir)
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
    bh_win_path_add $(winpath $android_cmd_dir/bin)
  fi
  if ! test -d $android_sdk_dir/platforms; then
    $android_cmd_dir/bin/sdkmanager.bat --sdk_root="$android_sdk_dir" --install 'platform-tools' 'platforms;android-29'
    yes | $android_cmd_dir/bin/sdkmanager.bat --sdk_root="$android_sdk_dir" --licenses
    bh_win_env_add ANDROID_HOME $(winpath $android_sdk_dir)
    bh_win_env_add ANDROID_SDK_ROOT $(winpath $android_sdk_dir)
    bh_win_path_add $(winpath $android_sdk_dir/platform-tools)
  fi

  # flutter
  local flutter_sdk_dir="$opt_dst/flutter"
  local flutter_sdk_url="https://storage.googleapis.com/flutter_infra_release/releases/stable/windows/flutter_windows_${BH_FLUTTER_VER}-stable.zip"
  if ! test -d $flutter_sdk_dir; then
    # opt_dst beacuase zip extract the flutter dir
    bh_decompress_from_url $flutter_sdk_url $opt_dst
    if test $? != 0; then bh_log_error "bh_decompress_from_url failed." && return 1; fi
    bh_win_path_add $(winpath $flutter_sdk_dir/bin)
  fi
}

function bh_install_win_latexindent() {
  bh_log_func
  if ! type latexindent.exe &>/dev/null; then
    bh_curl_fetch_to_dir https://github.com/cmhughes/latexindent.pl/releases/download/V3.10/latexindent.exe $BH_OPT_WIN/
    bh_curl_fetch_to_dir https://raw.githubusercontent.com/cmhughes/latexindent.pl/main/defaultSettings.yaml $BH_OPT_WIN/
  fi
}
