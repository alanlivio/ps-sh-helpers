#!/bin/bash

# ---------------------------------------
# aliases
# ---------------------------------------

alias unixpath='cygpath'
alias winpath='cygpath -w'
# fix mingw tmp
unset temp
unset tmp
# hide windows user files when ls home
alias ls='ls --color=auto --hide=ntuser* --hide=NTUSER* --hide=AppData --hide=IntelGraphicsProfiles* --hide=MicrosoftEdgeBackups'
alias chrome="/c/Program\ Files/Google/Chrome/Application/chrome.exe"
alias whereis='where'
alias reboot='gsudo shutdown \/r'
alias ps_call="powershell.exe -c"
alias ps_call_admin="gsudo powershell.exe -c"
alias ghostscript='gswin64c'

function bh_win_gitbash_fix_prompt {
  sed '/show\sMSYSTEM/d' -i /etc/profile.d/git-prompt.sh
}

function bh_open {
  local node="${1:-.}" # . is default value
  ps_call "Start-Process $node"
}

function bh_open_wt_settings() {
  bh_wt_stgs="$HOME/AppData/Local/Packages/Microsoft.WindowsTerminal_8wekyb3d8bbwe/LocalState/settings.json"
  code $bh_wt_stgs
}

function ps_call_script() {
  powershell.exe -c "& { . $1}"
}

function ps_call_script_admin() {
  gsudo powershell.exe -c "& { . $1}"
}

# ---------------------------------------
# user
# ---------------------------------------

function bh_win_user_check_admin() {
  # usage if [ "$(bh_win_user_check_admin)" == "True" ]; then <commands>; fi
  ps_call '
    $user = "$env:COMPUTERNAME\$env:USERNAME"
    $group = "Administrators"
    (Get-LocalGroupMember $group).Name -contains $user
  '
}

function bh_win_user_check_eleveated_shell() {
  ps_call '(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)' | tr -d '\rn'
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
# appx
# ---------------------------------------

function bh_win_appx_list_installed() {
  ps_call_admin "Get-AppxPackage -AllUsers | Select-Object Name, PackageFullName"
}

function bh_win_appx_uninstall() {
  ps_call_admin '
  if (Get-AppxPackage -Name ' "$1" ') {
    Get-AppxPackage' "$1" '| Remove-AppxPackage
  }
  '
}

function bh_win_appx_install() {
  ps_call_admin '
    Get-AppxPackage ' "$1" '| ForEach-Object { Add-AppxPackage -ea 0 -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" } | Out-null
  '
}

# ---------------------------------------
# services
# ---------------------------------------

function bh_win_services_list_running() {
  ps_call_admin 'Get-Service | Where-Object {$_.Status -eq "Running"}'
}

# ---------------------------------------
# env
# ---------------------------------------

function bh_win_env_show() {
  ps_call 'Get-ChildItem Env:'
}

function bh_win_env_add() {
  : ${2?"Usage: ${FUNCNAME[0]} <varname> <value>"}
  ps_call "[System.Environment]::SetEnvironmentVariable('$1', '$2', 'user')"
}

# ---------------------------------------
# path
# ---------------------------------------

function bh_win_path_show() {
  ps_call '(Get-ChildItem Env:Path).Value'
}

function bh_win_path_show_as_list() {
  IFS=';' read -ra ADDR <<<$(bh_win_path_show)
  for i in "${!ADDR[@]}"; do echo ${ADDR[$i]}; done
}

function bh_win_path_add() {
  local dir=$(winpath $@)
  ps_call ' 
    function bh_win_path_add($addDir) {
      $currentpath = [System.Environment]::GetEnvironmentVariable("PATH", "user")
      $regexAddPath = [regex]::Escape($addDir)
      $arrPath = $currentpath -split ";" | Sort-Object -Unique | Where-Object { $_ -notMatch "^$regexAddPath\\?" }
      $newpath = ($arrPath + $addDir) -join ";"
      [System.Environment]::SetEnvironmentVariable("PATH", $newpath, "user")
    }; bh_win_path_add ' \"$dir\"
}

function bh_win_path_remove() {
  local dir=$(winpath $@)
  ps_call ' 
    function bh_win_path_remove($remDir) {
      $currentpath = [System.Environment]::GetEnvironmentVariable("PATH", "user")
      $newpath = ($currentpath.Split(";") | Where-Object { $_ -ne "$remDir" }) -join ";"
      [System.Environment]::SetEnvironmentVariable("PATH", $newpath, "user")
    }; bh_win_path_remove ' \"$dir\"
}

function bh_win_path_add_winapps() {
  bh_win_path_add "$HOME/AppData/Local/Microsoft/WindowsApps/"
}

function bh_win_path_open_settings() {
  rundll32 sysdm.cpl,EditEnvironmentVariables &
}

# ---------------------------------------
# load commands
# ---------------------------------------

if type choco &>/dev/null; then source "$BH_DIR/lib/win/choco.sh"; fi
source "$BH_DIR/lib/win/sanity.sh"
source "$BH_DIR/lib/win/explorer.sh"
source "$BH_DIR/lib/win/install.sh"
source "$BH_DIR/lib/win/winget.sh"

# ---------------------------------------
# update_clean
# ---------------------------------------

function bh_update_cleanup_win() {
  # cleanup
  bh_home_clean_unused
  bh_win_explorer_hide_home_dotfiles
  # python
  type pip &>/dev/null && bh_python_install $BH_PKGS_PYTHON
  # vscode
  type code &>/dev/null && bh_vscode_install $BH_PKGS_VSCODE
  # windows
  type gsudo &>/dev/null && bh_win_sysupdate_win
  # winget (it uses --scope=user)
  bh_win_get_install $BH_PKGS_WINGET
}
