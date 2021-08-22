# ---------------------------------------
# install
# ---------------------------------------

function bh_install_docker() {
  bh_log_func
  ps_call_admin Enable-WindowsOptionalFeature -Online -FeatureName $("Microsoft-Hyper-V") -All
  ps_call_admin Enable-WindowsOptionalFeature -Online -FeatureName $("Containers") -All
  bh_win_get_install Docker.DockerDesktop
}

function bh_install_tesseract() {
  bh_log_func
  if type tesseract.exe &>/dev/null; then
    bh_win_get_install tesseract
    bh_win_path_add 'C:\Program Files\Tesseract-OCR'
  fi
}

function bh_install_java() {
  bh_log_func
  if type java.exe &>/dev/null; then
    bh_win_get_install ojdkbuild.ojdkbuild
    local javahome=$(ps_call '$(get-command java).Source.replace("\bin\java.exe", "")')
    bh_env_add "JAVA_HOME" "$javahome"
  fi
}

function bh_install_choco() {
  bh_log_func
  ps_call_admin '
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
    '
}

# ---------------------------------------
# choco helpers
# ---------------------------------------

if type gsudo &>/dev/null; then

  function bh_choco_install() {
    bh_log_func
    local pkgs_to_install=$(echo $@ | tr ' ' ';')
    gsudo choco install -y --acceptlicense $pkgs_to_install
  }

  function bh_choco_uninstall() {
    bh_log_func
    local pkgs_to_uninstall=$(echo $@ | tr ' ' ';')
    gsudo choco uninstall -y --acceptlicense $pkgs_to_uninstall
  }

  function bh_choco_upgrade() {
    bh_log_func
    local outdated=false
    gsudo choco outdated | grep '0 package' >/dev/null || outdated=true
    if $outdated; then gsudo choco upgrade -y --acceptlicense all; fi
  }

  function bh_choco_list_installed() {
    choco list -l
  }

  function bh_choco_clean() {
    bh_log_func
    if type choco-cleaner.exe &>/dev/null; then
      gsudo choco install choco-cleaner
    fi
    ps_call 'Invoke-Expression "$env:ChocolateyToolsLocation\BCURRAN3\choco-cleaner.ps1" | Out-Null'
  }
fi

# ---------------------------------------
# sysupdate helpers
# ---------------------------------------

function bh_win_sysupdate() {
  bh_log_func
  ps_call_admin '$(Install-WindowsUpdate -AcceptAll -IgnoreReboot) | Where-Object { 
    if ($_ -is [string]) {
      $_.Split("", [System.StringSplitOptions]::RemoveEmptyEntries) 
    } 
  }'
}
function bh_win_sysupdate_list() {
  ps_call_admin 'Get-WindowsUpdate'
}

function bh_win_sysupdate_list_last_installed() {
  ps_call_admin 'Get-WUHistory -Last 10 | Select-Object Date, Title, Result'
}
