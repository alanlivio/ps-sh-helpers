# ---------------------------------------
# choco
# ---------------------------------------

function bh_win_choco_setup() {
  choco feature disable -n checksumFiles
  choco feature disable -n showDownloadProgress
  choco feature disable -n showNonElevatedWarnings
  choco feature disable -n logValidationResultsOnWarnings
  choco feature disable -n logEnvironmentValues
  choco feature disable -n exitOnRebootDetected
  choco feature disable -n warnOnUpcomingLicenseExpiration
  choco feature enable -n stopOnFirstPackageFailure
  choco feature enable -n skipPackageUpgradesWhenNotInstalled
  choco feature enable -n logWithoutColor
  choco feature enable -n allowEmptyChecksumsSecure
  choco feature enable -n allowGlobalConfirmation
  choco feature enable -n failOnAutoUninstaller
  choco feature enable -n removePackageInformationOnUninstall
  choco feature enable -n useRememberedArgumentsForUpgrades
}

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
