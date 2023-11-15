function _log_msg () { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }

# system

function win_system_ver() {
    [Environment]::OSVersion.Version.ToString()
}

function win_system_disable_password_policy {
    $tmpfile = New-TemporaryFile
    secedit /export /cfg $tmpfile /quiet
  (Get-Content $tmpfile).Replace("PasswordComplexity = 1", "PasswordComplexity = 0").Replace("MaximumPasswordAge = 42", "MaximumPasswordAge = -1") | Out-File $tmpfile
    secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
    Remove-Item -Path $tmpfile
}

# sounds

function win_system_disable_beep() {
    Set-ItemProperty -Path "HKCU:\AppEvents\Schemes" -Name "(Default)" -Value ".None"
    net stop beep
}

# path

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

function win_policy_reset() {
    gsudo cmd.exe /C 'RD /S /Q %WinDir%\System32\GroupPolicyUsers '
    gsudo cmd.exe /C 'RD /S /Q %WinDir%\System32\GroupPolicy '
    gsudo gpupdate.exe /force
}

# env 

function win_env_add($name, $value) {
    gsudo [Environment]::SetEnvironmentVariable($name, $value, 'Machine')
}


function win_env_list() {
    [Environment]::GetEnvironmentVariables()
}

function win_env_path_list($addPath) {
    $path = [Environment]::GetEnvironmentVariable('path', 'Machine')
    Write-Output $path
}

# win_reg

function win_reg_open_path() {
    reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\ /v Lastkey /d 'Computer\\$1' /t REG_SZ /f
    regedit.exe
}

function win_reg_open_shell_folders() {
    win_reg_open_path 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
}

# edge

function win_edge_disable_ctrl_shift_c() {
    New-Item -Path 'HKCU:\Software\Policies\Microsoft\Edge' -Force | Out-Null
    Set-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Edge' -Name 'ConfigureKeyboardShortcuts' -Type String -Value  '{\"disabled\": [\"dev_tools_elements\"]}'
}

# optimize

function win_optimize_appx() {
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

# service

function win_scheduledtask_list_enabled() {
    Get-ScheduledTask | Where-Object { $_.State -eq "Ready" }
}


function win_service_list_running() {
    Get-Service | Where-Object { $_.Status -eq "Running" }
}


function win_service_ssh() {
    gsudo 'Set-Service ssh-agent -StartupType Automatic'
    gsudo 'Start-Service ssh-agent'
    gsudo 'Get-Service ssh-agent'
    gsudo 'ssh-add "$env:userprofile\\.ssh\\id_rsa"'
}

function win_service_disable($name) {
    foreach ($name in $args) {
        Get-Service -Name $name | Stop-Service -WarningAction SilentlyContinue
        Get-Service -Name $ame | Set-Service -StartupType Disabled -ea 0
    }
}

# winpackage

function win_package_list_enabled() {
    Get-WindowsPackage -Online | Where-Object PackageState -like Installed | ForEach-Object { $_.PackageName }
}

function win_package_disable_like() {
    foreach ($name in $args) {
        $pkgs = Get-WindowsPackage -Online | Where-Object PackageState -like Installed | Where-Object PackageName -like $name
        if ($pkgs) {
            $pkgs | ForEach-Object { Remove-WindowsPackage -Online -NoRestart $_ }
        }
    }
}

# appx

function win_appx_list_installed() {
    Get-AppxPackage -AllUsers | Select-Object Name, PackageFullName
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

function win_appx_install_essentials() {
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

# explorer

function win_explorer_restore_desktop() {
    if (Test-Path "${env:userprofile}\Desktop") {
        mkdir "${env:userprofile}\Desktop"
    }
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Desktop" /t REG_SZ /d "C:\Users\${env:username}\Desktop" /f
    reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Desktop" /t REG_EXPAND_SZ /d "${env:userprofile}\Desktop" /f
    attrib +r -s -h "${env:userprofile}\Desktop"
}

function win_home_hide_dotfiles() {
    Get-ChildItem "${env:userprofile}\.*" | ForEach-Object { $_.Attributes += "Hidden" }
}


function win_explorer_open_trash() {
    Start-Process explorer shell:recyclebinfolder
}

function win_explorer_restart() {
    taskkill /f /im explorer.exe | Out-Null
    Start-Process explorer.exe
}

# wsl

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


# keyboard

function win_keyboard_lang_stgs_open() {
    cmd /c "rundll32.exe Shell32,Control_RunDLL input.dll,,{C07337D3-DB2C-4D0B-9A93-B722A6C106E2}"
}

function win_keyboard_disable_shortcut_lang {
    Set-ItemProperty -Path 'HKCU:\Keyboard Layout\Toggle' -Name HotKey -Value 3
    Set-ItemProperty -Path 'HKCU:\Keyboard Layout\Toggle' -Name "Language Hotkey" -Value 3
}

function win_keyboard_disable_shortcut_altgr() {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Keyboard Layout" -Name "Scancode Map" -Value ([byte[]](0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x38, 0x00, 0x38, 0xe0, 0x00, 0x00, 0x00, 0x00))
}