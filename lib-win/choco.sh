# ---------------------------------------
# choco helpers
# ---------------------------------------

function bh_choco_install() {
  bh_log_func
  local pkgs_to_install=$(echo $@ | tr ' ' ';')
  sudo choco install -y --acceptlicense $pkgs_to_install
}

function bh_choco_uninstall() {
  bh_log_func
  local pkgs_to_uninstall=$(echo $@ | tr ' ' ';')
  sudo choco uninstall -y --acceptlicense $pkgs_to_uninstall
}

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
