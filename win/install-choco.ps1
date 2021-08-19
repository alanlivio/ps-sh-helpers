function bh_log() {
  Write-Host -ForegroundColor DarkYellow "--" ($args -join " ")
}

# ---------------------------------------
# install_choco
# ---------------------------------------
bh_log "bh_win_install_choco"
if (!(Get-Command 'choco.exe' -ea 0)) {
  Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
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
  # enable use without restarting Powershell
}