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
      winget install $pkg
      if [ $? -gt 0 ]; then
        bh_log_msg "INFO: winget install failed, trying winget install -i ..."
        winget install -i $pkg
      fi
    done
  fi
}

function bh_win_get_settings() {
  winget settings
}

function bh_win_get_upgrade() {
  winget upgrade --all --silent
}
