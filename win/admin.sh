# ---------------------------------------
# user
# ---------------------------------------

function bh_win_user_disable_password_policy() {
  ps_call_script_admin $(unixpath -w $BH_DIR/win/admin/disable-password-policy.ps1)
}

function bh_win_disable_ctx_menu_unused() {
  ps_call_script_admin $(unixpath -w $BH_DIR/win/admin/disable-cxt-menu-unused.ps1)
}

function bh_win_user_adminstrator_enable() {
  ps_call_admin 'net user administrator /active:yes'
}

function bh_win_user_adminstrator_disable() {
  ps_call_admin 'net user administrator /active:no'
}

# ---------------------------------------
# sysupdate
# ---------------------------------------

function bh_win_sysupdate_win() {
  bh_log_func
  ps_call_admin '
    Install-Module -Name PSWindowsUpdate -Force
    $(Install-WindowsUpdate -AcceptAll -IgnoreReboot) | Where-Object { 
    if ($_ -is [string]) {
      $_.Split("", [System.StringSplitOptions]::RemoveEmptyEntries) 
    } 
  }'
}

function bh_win_sysupdate_win_list() {
  ps_call_admin 'Get-WindowsUpdate'
}

function bh_win_sysupdate_win_list_last_installed() {
  ps_call_admin 'Get-WUHistory -Last 10 | Select-Object Date, Title, Result'
}

# ---------------------------------------
# feature
# ---------------------------------------

function bh_win_feature_disable_unused_services_features() {
  ps_call_script_admin $(unixpath -w $BH_DIR/win/admin/disable-unused-services-features.ps1)
}

function bh_win_feature_enable_ssh_server_pwsh() {
  ps_call_script_admin $(unixpath -w $BH_DIR/win/admin/enable-ssh-server-pwsh.ps1)
}

function bh_win_feature_enable_ssh_server_gitbash() {
  bh_log_func
  local gitbash_path=$(whereis bash | head -1)
  ps_call_admin "
    Add-WindowsCapability -Online -Name OpenSSH.Client
    Add-WindowsCapability -Online -Name OpenSSH.Server
    Start-Service sshd
    Set-Service -Name sshd -StartupType 'Automatic'
    New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value '$gitbash_path' -PropertyType String -Force
  "
}

function bh_win_feature_list_enabled() {
  bh_log_msg "WindowsOptionalFeatures"
  ps_call_admin 'Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Enabled"}'
  bh_log_msg "WindowsCapabilities"
  ps_call_admin 'Get-WindowsCapability -Online | Where-Object {$_.State -eq "Installed"}'
}

function bh_win_feature_list_disabled() {
  bh_log_msg "WindowsOptionalFeatures"
  ps_call_admin 'Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq "Disabled"}'
  bh_log_msg "WindowsCapabilities"
  ps_call_admin 'Get-WindowsCapability -Online | Where-Object {$_.State -eq "NotPresent"}'
}

# ---------------------------------------
# services
# ---------------------------------------

function bh_win_services_list_running() {
  ps_call_admin 'Get-Service | Where-Object {$_.Status -eq "Running"}'
}

# ---------------------------------------
# install admin
# ---------------------------------------

function bh_install_win_gsudo() {
  bh_win_get_install gsudo
}

function bh_install_win_wsl() {
  ps_call_script_admin $(unixpath -w $BH_DIR/win/admin/install-wsl.ps1)
}

function bh_install_win_msys() {
  ps_call_script_admin $(unixpath -w $BH_DIR/win/admin/install-msys.ps1)
}

function bh_install_win_tesseract() {
  bh_log_func
  if type tesseract.exe &>/dev/null; then
    bh_win_get_install tesseract
    bh_path_win_add 'C:\Program Files\Tesseract-OCR'
  fi
}

function bh_install_win_java() {
  bh_log_func
  if type java.exe &>/dev/null; then
    bh_win_get_install ojdkbuild.ojdkbuild
    local javahome=$(ps_call '$(get-command java).Source.replace("\bin\java.exe", "")')
    bh_env_add "JAVA_HOME" "$javahome"
  fi
}

function bh_install_win_docker() {
  bh_log_func
  ps_call_admin Enable-WindowsOptionalFeature -Online -FeatureName $("Microsoft-Hyper-V") -All
  ps_call_admin Enable-WindowsOptionalFeature -Online -FeatureName $("Containers") -All
  bh_win_get_install Docker.DockerDesktop
}

function bh_install_win_choco() {
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
# choco
# ---------------------------------------

function bh_choco_list_installed() {
  choco list -l
}

function bh_choco_list_installed_str() {
  powershell -c '
      $pkgs = $(choco list -l | ForEach-Object { $_.split(' ')[0] }) -join (" ")
      echo $pkgs
    '
}

function bh_choco_install() {
  bh_log_func
  local pkgs_to_install=""
  local pkgs_installed=$(bh_choco_list_installed_str)
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

function bh_choco_clean() {
  bh_log_func
  if ! type choco-cleaner.exe &>/dev/null; then
    bh_choco_install choco-cleaner
  fi
  ps_call_admin 'Invoke-Expression "$env:ChocolateyToolsLocation\BCURRAN3\choco-cleaner.ps1" | Out-Null'
}
