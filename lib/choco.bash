function choco_list_installed() {
  choco list -l
}

function choco_list_installed_str() {
  powershell -c '$(choco list -l | ForEach-Object { $_.split(' ')[0] }) -join (" ")'
}

function choco_config() {
  powershell -c '
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
  '
}

function choco_install() {
  local pkgs_to_install=""
  local pkgs_installed=$(choco_list_installed_str)
  for i in "$@"; do
    if [[ ! $pkgs_installed =~ $i ]]; then
      pkgs_to_install="$i $pkgs_to_install"
    fi
  done
  if test ! -z "$pkgs_to_install"; then
    log_msg "pkgs_to_install=$pkgs_to_install"
    for pkg in $pkgs_to_install; do
      gsudo choco install -y --acceptlicense $pkg
    done
  fi
}

function choco_uninstall() {
  local pkgs_to_uninstall=$(echo $@ | tr ' ' ';')
  gsudo choco uninstall -y --acceptlicense $pkgs_to_uninstall
}

function choco_upgrade() {
  local outdated=false
  gsudo choco outdated | grep '0 package' >/dev/null || outdated=true
  if $outdated; then gsudo choco upgrade -y --acceptlicense all; fi
}

function choco_clean() {
  if ! type choco-cleaner.exe &>/dev/null; then
    choco_install choco-cleaner
  fi
  ps_call_admin 'Invoke-Expression "$env:ChocolateyToolsLocation\BCURRAN3\choco-cleaner.ps1" | Out-Null'
}
