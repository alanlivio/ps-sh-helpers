# -- essentials --

function _log_msg () { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }

function win_update() {
    _log_msg "winget upgrade all"
    winget upgrade --all
    _log_msg "win os upgrade"
    $(gsudo Install-WindowsUpdate -AcceptAll -IgnoreReboot) | Where-Object { 
        if ($_ -is [string]) {
            $_.Split('', [System.StringSplitOptions]::RemoveEmptyEntries) 
        } 
    }
}


# -- path --

function win_path_add($addPath) {
    if (Test-Path $addPath) {
        $path = [Environment]::GetEnvironmentVariable('path', 'Machine')
        $regexAddPath = [regex]::Escape($addPath)
        $arrPath = $path -split ';' | Where-Object { $_ -notMatch "^$regexAddPath\\?" }
        $newpath = ($arrPath + $addPath) -join ';'
        [Environment]::SetEnvironmentVariable("path", $newpath, 'Machine')
    }
    else {
        Throw "$addPath' is not a valid path."
    }
}

function win_path_list() {
    (Get-ChildItem Env:Path).Value -split ';'
}

function win_path_refresh() {
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User") 
}

function win_policy_reset() {
    gsudo cmd.exe /C 'RD /S /Q %WinDir%\System32\GroupPolicyUsers '
    gsudo cmd.exe /C 'RD /S /Q %WinDir%\System32\GroupPolicy '
    gsudo gpupdate.exe /force
}

# -- env  --

function win_env_add($name, $value) {
    gsudo [Environment]::SetEnvironmentVariable($name, $value, 'Machine')
}

function win_env_list() {
    [Environment]::GetEnvironmentVariables()
}

# -- reg --

function win_reg_open_path() {
    reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\ /v Lastkey /d 'Computer\\$1' /t REG_SZ /f
    regedit.exe
}

function win_reg_open_shell_folders() {
    win_reg_open_path 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
}

# -- explorer --

function win_explorer_restore_desktop() {
    if (Test-Path "${env:userprofile}\Desktop") {
        mkdir "${env:userprofile}\Desktop"
    }
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Desktop" /t REG_SZ /d "C:\Users\${env:username}\Desktop" /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Desktop" /t REG_EXPAND_SZ /d "${env:userprofile}\Desktop" /f
    attrib +r -s -h "${env:userprofile}\Desktop"
}

function win_explore_hide_home_dotfiles() {
    Get-ChildItem "${env:userprofile}\.*" | ForEach-Object { $_.Attributes += "Hidden" }
}

function win_explorer_open_trash() {
    Start-Process explorer shell:recyclebinfolder
}

function win_explorer_restart() {
    taskkill /f /im explorer.exe | Out-Null
    Start-Process explorer.exe
}

# -- wsl --

function win_wsl_list() {
    wsl -l -v
}

function win_wsl_list_running() {
    wsl -l -v --running
}

function win_wsl_get_default() {
    [System.Text.Encoding]::Unicode.GetString([System.Text.Encoding]::UTF8.GetBytes((wsl -l))) -split '\s\s+' | ForEach-Object {
        if ($_.Contains('(')) {
            return $_.Split(' ')[0]
        }
    }
}

function win_wsl_get_default_version() {
    Foreach ($i in (wsl -l -v)) {
        if ($i.Contains('*')) {
            return $i.Split(' ')[-1]
        }
    }
}

function win_wsl_terminate() {
    wsl -t (wsl_get_default)
}

# -- system --

function win_appx_list_installed() {
    Get-AppxPackage -AllUsers | ForEach-Object { Write-Output $_.Name }
}

function win_appx_install() {
    $pkgs_to_install = ""
    foreach ($name in $args) {
        if ( !(Get-AppxPackage -Name $name)) {
            $pkgs_to_install = "$pkgs_to_install $name"
        }
    }
    if ($pkgs_to_install) {
        _log_msg "pkgs_to_install=$pkgs_to_install"
        foreach ($pkg in $pkgs_to_install) {
            Get-AppxPackage -allusers $pkg | ForEach-Object { Add-AppxPackage -ea 0 -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" } | Out-null
        }
    }
}

function win_appx_uninstall() {
    foreach ($name in $args) {
        if (Get-AppxPackage -Name $name) {
            _log_msg "uninstall $name"
            Get-AppxPackage -allusers $name | Remove-AppxPackage
        }
    }
}


function win_service_disable($name) {
    foreach ($name in $args) {
        Get-Service -Name $name | gsudo Stop-Service -WarningAction SilentlyContinue
        Get-Service -Name $ame | gsudo Set-Service -StartupType Disabled -ea 0
    }
}

# -- system disable --

function win_disable_protocol_execute_warning() {
    New-Item -Path "HKCU:\Software\Microsoft\Internet Explorer\ProtocolExecute\onenote" -Force | Out-Null
    New-Item -Path "HKCU:\Software\Microsoft\Internet Explorer\ProtocolExecute\onenotedesktop" -Force | Out-Null
    New-Item -Path "HKCU:\Software\Microsoft\Internet Explorer\ProtocolExecute\onenote-cmd" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\ProtocolExecute\onenote" -Name 'WarnOnOpen ' -Type DWORD -Value '0'
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\ProtocolExecute\onenotedesktop" -Name 'WarnOnOpen ' -Type DWORD -Value '0'
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\ProtocolExecute\onenote-cmd" -Name 'WarnOnOpen ' -Type DWORD -Value '0'
}

function win_disable_password_policy() {
    $tmpfile = New-TemporaryFile
    gsudo secedit /export /cfg $tmpfile /quiet
  (Get-Content $tmpfile).Replace("PasswordComplexity = 1", "PasswordComplexity = 0").Replace("MaximumPasswordAge = 42", "MaximumPasswordAge = -1") | Out-File $tmpfile
    gsudo secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
    Remove-Item -Path $tmpfile
}

function win_disable_file_search() {
    gsudo cmd.exe /c 'sc stop "wsearch"'
    gsudo cmd.exe /c 'sc config "wsearch" start=disabled'
}

function win_disable_web_search_and_widgets() {
    _log_msg "disable Web Search"
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name 'BingSearchEnabled' -Type DWORD -Value '0'
    gsudo New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
    gsudo Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name 'DisableSearchBoxSuggestions' -Type DWORD -Value '1'
    _log_msg "disable Web Widgets"
    winget.exe uninstall MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy
}

function win_disable_sounds() {
    Set-ItemProperty -Path "HKCU:\AppEvents\Schemes" -Name "(Default)" -Value ".None"
    gsudo net stop beep
}

function win_disable_edge_ctrl_shift_c() {
    gsudo New-Item -Path 'HKCU:\Software\Policies\Microsoft\Edge' -Force | Out-Null
    gsudo Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Edge' -Name 'ConfigureKeyboardShortcuts' -Type String -Value  '{\"disabled\": [\"dev_tools_elements\"]}'
}

function win_disable_shortcuts_unused() {
    _log_msg "disable altgr shorcuts"
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Keyboard Layout" -Name "Scancode Map" -Value ([byte[]](0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x38, 0x00, 0x38, 0xe0, 0x00, 0x00, 0x00, 0x00))
    
    _log_msg "disable acessibility shorcuts"
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name 'Flags' -Type String -Value '58'
    New-Item -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name 'Flags' -Type String -Value '122'
    
    _log_msg "disable AutoRotation shorcuts"
    reg add "HKCU\Software\INTEL\DISPLAY\IGFXCUI\HotKeys" /v "Enable" /t REG_DWORD /d 0 /f | Out-Null
    
    _log_msg "disable language shorcuts"
    Set-ItemProperty -Path 'HKCU:\Keyboard Layout\Toggle' -Name "HotKey" -Value 3
    Set-ItemProperty -Path 'HKCU:\Keyboard Layout\Toggle' -Name "Language Hotkey" -Value 3
    Set-ItemProperty -Path 'HKCU:\Keyboard Layout\Toggle' -Name "Layout Hotkey" -Value 3
    
    # explorer restart
    _log_msg "explorer restart"
    Stop-Process -ProcessName explorer -ea 0 | Out-Null
}


function win_disable_osapps_unused() {
    # microsoft
    $pkgs = @(
        'MicrosoftTeams'
        'Microsoft.3DBuilder'
        'Microsoft.Appconnector'
        'Microsoft.BingNews'
        'Microsoft.BingSports'
        'Microsoft.BingWeather'
        'Microsoft.CommsPhone'
        'Microsoft.ConnectivityStore'
        'Microsoft.GamingApp'
        'Microsoft.MSPaint'
        'Microsoft.Microsoft3DViewer'
        'Microsoft.MicrosoftOfficeHub'
        'Microsoft.MicrosoftSolitaireCollection'
        'Microsoft.MicrosoftStickyNotes'
        'Microsoft.MixedReality.Portal'
        'Microsoft.OneConnect'
        'Microsoft.People'
        'Microsoft.PowerAutomateDesktop'
        'Microsoft.Print3D'
        'Microsoft.SkypeApp'
        'Microsoft.StorePurchaseApp'
        'Microsoft.Wallet'
        'Microsoft.WindowsMaps'
        'Microsoft.Xbox.TCUI'
        'Microsoft.XboxApp'
        'Microsoft.XboxGameOverlay'
        'Microsoft.XboxGamingOverlay'
        'Microsoft.XboxIdentityProvider'
        'Microsoft.XboxSpeechToTextOverlay'
        'Microsoft.YourPhone'
        'Microsoft.ZuneMusic'
    )
    appx_uninstall @pkgs
}

# -- system enable --

function win_enable_osapps_essentials() {
    $pkgs = @(
        'Microsoft.WindowsStore'
        'Microsoft.WindowsCalculator'
        'Microsoft.Windows.Photos'
        'Microsoft.WindowsFeedbackHub'
        'Microsoft.WindowsCamera'
        'Microsoft.WindowsSoundRecorder'
    )
    appx_install @pkgs
}

function win_enable_hyperv() {
    gsudo dism /online /enable-feature /featurename:Microsoft-Hyper-V -All /LimitAccess /ALL
}


function win_enable_ssh_service() {
    gsudo Set-Service ssh-agent -StartupType Automatic
    gsudo Start-Service ssh-agent
    gsudo Get-Service ssh-agent
    ssh-add "$env:userprofile\\.ssh\\id_rsa"
}