# -- essentials --


function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }
function log_error() { Write-Host -ForegroundColor DarkRed "--" ($args -join " ") }
function has_sudo() { if (Get-Command sudo -errorAction SilentlyContinue) { return $true } else { return $false } }

function win_enable_sudo() {
    if (-Not(Get-Command sudo -errorAction SilentlyContinue)) {
        # win 11 support native sudo https://learn.microsoft.com/en-us/windows/sudo/
        if ((Get-ComputerInfo | Select-Object -expand OsName) -match 11) {
            sudo config --enable
        }
        # win 10 support from https://github.com/gerardog/gsudo
        else {
            winget install gsudo
        }
        win_path_refresh
    }
}

function win_update() {
    log_msg "win_update"
    if (-Not (has_sudo)) { log_error "no sudo. skipping."; return }
    log_msg "> winget upgrade"
    winget upgrade --accept-package-agreements --accept-source-agreements --silent --all
    log_msg "> os upgrade"
    if (-Not (has_sudo)) { 
        log_error "no sudo for os upgrade. starting settings manually"
        explorer.exe ms-settings:windowsupdate-action
    }
    sudo {
        # https://gist.github.com/billpieper/a39173afa0b343a14ddeeb1d79ab14ea
        if (-Not(Get-Command Install-WindowsUpdate -errorAction SilentlyContinue)) {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            Install-Module -Name PSWindowsUpdate -Scope CurrentUser -Force
            # Add-WUServiceManager -MicrosoftUpdate -Confirm:$false | Out-Null
        }
        $(Install-WindowsUpdate -AcceptAll -IgnoreReboot) | Where-Object {
            if ($_ -is [string]) {
                $_.Split('', [System.StringSplitOptions]::RemoveEmptyEntries)
            }
        }
    }
}

function win_install_ubuntu() {
    if (-Not (has_sudo)) { log_error "no sudo. skipping."; return }
    wsl --set-default-version 2
    sudo wsl --update
    sudo wsl --install -d Ubuntu
}

function winget_install() {
    winget list -q $Args[0] | Out-Null
    if (-not $?) {
        winget install $Args[0] --accept-package-agreements --accept-source-agreements --scope "user"
    }
}

function winget_install_at_location() {
    winget list -q $Args[0] | Out-Null
    if (-not $?) {
        winget install $Args[0] --accept-package-agreements --accept-source-agreements --scope "user" --location="$Args[1]"
    }
}

function winget_uninstall() {
    winget list -q $Args | Out-Null
    if ($?) {
        winget uninstall --silent "$Args"
    }
}

function ps_profile_reload() {
    @(
        $profile.AllUsersAllHosts,
        $profile.AllUsersCurrentHost,
        $profile.CurrentUserAllHosts,
        $profile.CurrentUserCurrentHost
    ) | ForEach-Object {
        if (Test-Path $_) {
            Write-Output "loading $_"
            Import-Module -Force -Global $_ #-Verbose 
        }
    }
}

function ps_show_function($name) {
    Get-Content Function:\$name
}

function win_hlink_create($path, $target) {
    New-Item -ItemType Hardlink -Force -Path $path -Target $target
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

# -- env  --

function win_env_add($name, $value) {
    [Environment]::SetEnvironmentVariable($name, $value, 'User')
}

function win_env_add_machine($name, $value) {
    if (-Not (has_sudo)) { log_error "no sudo. skipping."; return }
    sudo {
        [Environment]::SetEnvironmentVariable($name, $value, 'Machine')
    }
}

function win_env_list() {
    [Environment]::GetEnvironmentVariables()
}

# -- explorer --

function win_onedrive_reset() {
    & "C:\Program Files\Microsoft OneDrive\onedrive.exe" /reset
}

function win_explorer_hide_home_dotfiles() {
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

function wsl_list() {
    wsl -l -v
}

function wsl_list_running() {
    wsl -l -v --running
}

function wsl_get_default() {
    [System.Text.Encoding]::Unicode.GetString([System.Text.Encoding]::UTF8.GetBytes((wsl -l))) -split '\s\s+' | ForEach-Object {
        if ($_.Contains('(')) {
            return $_.Split(' ')[0]
        }
    }
}

function wsl_get_default_version() {
    Foreach ($i in (wsl -l -v)) {
        if ($i.Contains('*')) {
            return $i.Split(' ')[-1]
        }
    }
}

function wsl_terminate() {
    wsl -t (wsl_get_default)
}

# -- system --

function win_image_cleanup() {
    if (-Not (has_sudo)) { log_error "no sudo. skipping."; return }
    sudo { dism /Online /Cleanup-Image /RestoreHealth }
}

function win_policy_reset() {
    if (-Not (has_sudo)) { log_error "no sudo. skipping."; return }
    sudo {
        cmd.exe /C 'RD /S /Q %WinDir%\System32\GroupPolicyUsers '
        cmd.exe /C 'RD /S /Q %WinDir%\System32\GroupPolicy '
        gpupdate.exe /force
    }
}

function win_enable_insider_beta() {
    # https://www.elevenforum.com/t/change-windows-insider-program-channel-in-windows-11.795/
    bcdedit /set flightsigning on
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsSelfHost\Applicability" -Name "BranchName" -Value 'Beta'
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsSelfHost\Applicability" -Name "ContentType" -Value 'Mainline'
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsSelfHost\Applicability" -Name "Ring" -Value 'External'
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsSelfHost\UI\Selection" -Name "UIBranch" -Value 'Beta'
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsSelfHost\UI\Selection" -Name "UIContentType" -Value 'Mainline'
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsSelfHost\UI\Selection" -Name "UIRing" -Value 'External'
}

function win_enable_dark_no_transparency() {
    $reg_personalize = "HKCU:Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    Set-ItemProperty -Path $reg_personalize -Name "SystemUsesLightTheme" -Value  '0' -Type 'DWORD'
    Set-ItemProperty -Path $reg_personalize -Name "EnableTransparency" -Value  '0' -Type 'DWORD'
    Set-ItemProperty -Path $reg_personalize -Name "SystemUsesLightTheme" -Value  '0' -Type 'DWORD'
    Set-ItemProperty -Path $reg_personalize -Name "ColorPrevalence" -Value  '0' -Type 'DWORD'
}

function win_appx_list_installed() {
    Get-AppxPackage -User $env:username | ForEach-Object { Write-Output $_.Name }
}

function win_appx_install() {
    $pkgs_to_install = ""
    foreach ($name in $args) {
        if (-Not (Get-AppxPackage -User $env:username -Name $name)) {
            $pkgs_to_install = "$pkgs_to_install $name"
        }
    }
    if ($pkgs_to_install) {
        log_msg "pkgs_to_install=$pkgs_to_install"
        foreach ($pkg in $pkgs_to_install) {
            Get-AppxPackage -User $env:username -Name $pkg | ForEach-Object { Add-AppxPackage -ea 0 -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" } | Out-null
        }
    }
}

function win_appx_uninstall() {
    foreach ($name in $args) {
        if (Get-AppxPackage -User $env:username -Name $name) {
            log_msg "uninstall $name"
            Get-AppxPackage -User $env:username -Name $name | Remove-AppxPackage
        }
    }
}

# -- system disable --

function win_disable_osapps_unused() {
    log_msg "win_disable_osapps_unused"
    
    # old appx not avaliable in winget, most for win10
    $pkgs = @(
        'Clipchamp.Clipchamp'
        'Microsoft.BingNews'
        'Microsoft.BingSports'
        'Microsoft.BingWeather'
        'Microsoft.Getstarted'
        'Microsoft.Microsoft3DViewer'
        'Microsoft.MicrosoftSolitaireCollection'
        'Microsoft.MicrosoftStickyNotes'
        'Microsoft.MixedReality.Portal'
        'Microsoft.People'
        'Microsoft.Wallet'
        'microsoft.windowscommunicationsapps'
        'Microsoft.WindowsMaps'
        'Microsoft.YourPhone'
        'Microsoft.ZuneMusic'
        'Microsoft.ZuneVideo'
        'SpotifyAB.SpotifyMusic'
    )
    win_appx_uninstall @pkgs
    
    # avaliable in winget
    winget_uninstall Microsoft.BingWallpaper
    winget_uninstall Microsoft.ZuneVideo_8wekyb3d8bbwe
    winget_uninstall Microsoft.MSPaint_8wekyb3d8bbwe
    winget_uninstall Microsoft.Skype
    winget_uninstall Microsoft.PowerAutomateDesktop
}

function win_disable_password_policy() {
    log_msg "win_disable_password_policy"
    if (-Not (has_sudo)) { log_error "no sudo. skipping."; return }
    sudo {
        $tmpfile = New-TemporaryFile
        secedit /export /cfg $tmpfile /quiet # this call requires admin
        (Get-Content $tmpfile).Replace("PasswordComplexity = 1", "PasswordComplexity = 0").Replace("MaximumPasswordAge = 42", "MaximumPasswordAge = -1") | Out-File $tmpfile
        secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
        Remove-Item -Path $tmpfile
    }
}

function win_disable_shortcuts_unused() {
    log_msg "win_disable_shortcuts_unused"
    
    # "disable AutoRotation shorcuts"
    Set-ItemProperty -Path "HKCU:\Software\Intel\Display\Igfxcui" -Name "HotKeys" -Value 'Enable'

    # "disable language shorcuts"
    $reg_key_toggle = "HKCU:\Keyboard Layout\Toggle"
    Set-ItemProperty -Path $reg_key_toggle -Name "HotKey" -Value '3' -Type 'DWORD'
    Set-ItemProperty -Path $reg_key_toggle -Name "Language Hotkey" -Value '3' -Type 'DWORD'
    Set-ItemProperty -Path $reg_key_toggle -Name "Layout Hotkey" -Value '3' -Type 'DWORD'

    # "disable acessibility shorcuts"
    $reg_acess = "HKCU:\Control Panel\Accessibility"
    Set-ItemProperty -Path "$reg_acess\ToggleKeys" -Name "Flags" -Value '58' -Type 'DWORD'
    New-Item -Path "$reg_acess\Keyboard Response" -Force | Out-Null
    Set-ItemProperty -Path "$reg_acess\Keyboard Response" -Name "Flags" -Value '122' -Type 'DWORD'

    # explorer restart
    Stop-Process -ProcessName explorer -ea 0 | Out-Null
}

function win_disable_sounds() {
    log_msg "win_disable_sounds"
    Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\" "(Default)" -Value ".None"
    Get-ChildItem -Path 'HKCU:\AppEvents\Schemes\Apps' | Get-ChildItem | Get-ChildItem | Where-Object { $_.PSChildName -eq '.Current' } | Set-ItemProperty -Name '(Default)' -Value '' 
}

function win_disable_web_search_and_widgets() {
    log_msg "win_disable_web_search_and_widgets"
    # win 11
    if ((Get-ComputerInfo | Select-Object -expand OsName) -match 11) {
        winget list -q "MicrosoftWindows.Client.WebExperience_cw5n1h2txyew" | Out-Null
        if ($?) { winget.exe uninstall MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy }
        # https://www.tomshardware.com/how-to/disable-windows-web-search
        if (-Not (has_sudo)) { log_error "no sudo. skipping DisableSearchBoxSuggestions at win 11 ."; return }
        sudo {
            $reg_explorer_pols = "HKCU:\Software\Policies\Microsoft\Windows\Explorer"
            New-Item -Path $reg_explorer_pols -Force | Out-Null
            Set-ItemProperty -Path $reg_explorer_pols -Name 'DisableSearchBoxSuggestions' -Value '1' -Type 'DWORD'
        }
    }
    else {
        # win 10
        # https://www.bennetrichter.de/en/tutorials/windows-10-disable-web-search/
        $reg_search = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
        Set-ItemProperty -Path "$reg_search" -Name 'BingSearchEnabled' -Value '0' -Type 'DWORD'
        $reg_search2 = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'
        Set-ItemProperty -Path "$reg_search2" -Name 'IsDynamicSearchBoxEnabled' -Value '0' -Type 'DWORD'
    }
}

function win_disable_edge_ctrl_shift_c() {
    log_msg "win_disable_edge_ctrl_shift_c"
    if (-Not (has_sudo)) { log_error "no sudo. skipping."; return }
    sudo {
        $reg_edge_pol = "HKCU:\Software\Policies\Microsoft\Edge"
        New-Item -Path $reg_edge_pol -Force | Out-Null
        if (-not (Get-ItemPropertyValue -Path $reg_edge_pol -Name 'ConfigureKeyboardShortcuts')) {
            Set-ItemProperty -Path $reg_edge_pol -Name 'ConfigureKeyboardShortcuts' -Value '{"disabled": ["dev_tools_elements"]}'
            gpupdate.exe /force
        }
    }
}

function win_disable_explorer_clutter() {
    log_msg "win_disable_explorer_clutter"
    $reg_explorer = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
    # setup folder listing
    Set-ItemProperty -Path $reg_explorer -Name ShowFrequent -Value '0' -Type 'DWORD'
    Set-ItemProperty -Path $reg_explorer -Name ShowRecent -Value '0' -Type 'DWORD'
    Set-ItemProperty -Path $reg_explorer -Name ShowRecommendations -Value '0' -Type 'DWORD'
    Set-ItemProperty -Path $reg_explorer -Name HideFileExt -Value '0' -Type 'DWORD'
}

function win_disable_taskbar_clutter() {
    log_msg "win_disable_taskbar_clutter"
    $reg_explorer_adv = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    
    # taskbar
    # https://www.askvg.com/disable-or-remove-extra-icons-and-buttons-from-windows-11-taskbar
    Set-ItemProperty -Path $reg_explorer_adv -Name ShowTaskViewButton -Value '0' -Type 'DWORD'
    Set-ItemProperty -Path $reg_explorer_adv -Name TaskbarDa -Value '0' -Type 'DWORD'
    Set-ItemProperty -Path $reg_explorer_adv -Name TaskbarMn -Value '0' -Type 'DWORD'
    Set-ItemProperty -Path $reg_explorer_adv -Name ShowCopilotButton -Value '0' -Type 'DWORD'
    Set-ItemProperty -Path $reg_explorer_adv -Name UseCompactMode -Value '1' -Type 'DWORD'
    Set-ItemProperty -Path $reg_explorer_adv -Name ShowStatusBar -Value '1' -Type 'DWORD'
    Set-ItemProperty -Path $reg_explorer_adv -Name TaskbarAI -Value '0' -Type 'DWORD'
    Set-ItemProperty -Path $reg_explorer_adv -Name TaskbarBadges -Value '0' -Type 'DWORD'
    Set-ItemProperty -Path $reg_explorer_adv -Name TaskbarAnimations -Value '0' -Type 'DWORD'

    # multitasking
    # https://www.itechtics.com/disable-edge-tabs-alt-tab
    Set-ItemProperty -Path $reg_explorer_adv -Name MultiTaskingAltTabFilter -Value '3' -Type 'DWORD'
    # https://superuser.com/questions/1516878/how-to-disable-windows-snap-assist-via-command-line
    Set-ItemProperty -Path $reg_explorer_adv -Name SnapAssist -Value '0' -Type 'DWORD'
    
    # search
    $reg_search = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
    Set-ItemProperty -Path $reg_search -Name SearchBoxTaskbarMode -Value '0' -Type 'DWORD'
}

function win_disable_copilot() {
    sudo {
        $reg_explorer_pols = "HKCU:\Software\Policies\Microsoft\Windows"
        New-Item -Path "$reg_explorer_pols\WindowsCopilot" -Force | Out-Null
        Set-ItemProperty -Path "$reg_explorer_pols\WindowsCopilot" -Name 'TurnOffWindowsCopilot' -Value '1' -Type 'DWORD'
    }
}

function win_disable_gaming_clutter() {
    log_msg "win_disable_gaming_clutter"
    # https://www.makeuseof.com/windows-new-app-ms-gamingoverlay-error/

    $reg_game_dvr = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"
    Set-ItemProperty -Path $reg_game_dvr -Name AppCaptureEnabled -Value '0' -Type 'DWORD'
    Set-ItemProperty -Path $reg_game_dvr -Name HistoricalCaptureEnabled -Value '0' -Type 'DWORD'
    $reg_game_store = "HKCU:\System\GameConfigStore"
    Set-ItemProperty -Path $reg_game_store -Name GameDVR_Enabled -Value '0' -Type 'DWORD'

    winget_uninstall Microsoft.Xbox.TCUI_8wekyb3d8bbwe
    winget_uninstall Microsoft.XboxApp_8wekyb3d8bbwe
    winget_uninstall Microsoft.XboxGameOverlay_8wekyb3d8bbwe
    winget_uninstall Microsoft.XboxGamingOverlay_8wekyb3d8bbwe
    winget_uninstall Microsoft.XboxIdentityProvider_8wekyb3d8bbwe
    winget_uninstall Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe
}

# -- system enable --

function win_enable_osapps_essentials() {
    log_msg "win_enable_osapps_essentials"
    $pkgs = @(
        'Microsoft.WindowsStore'
        'Microsoft.WindowsCalculator'
        'Microsoft.Windows.Photos'
        'Microsoft.WindowsFeedbackHub'
        'Microsoft.WindowsCamera'
    )
    win_appx_install @pkgs
}

function win_enable_hyperv() {
    if (-Not (has_sudo)) { log_error "no sudo. skipping."; return }
    sudo { dism /online /enable-feature /featurename:Microsoft-Hyper-V -All /LimitAccess /ALL }
}


function win_ssh_agent_and_add_id_rsa() {
    if (-Not (has_sudo)) { log_error "no sudo. skipping."; return }
    sudo {
        Set-Service ssh-agent -StartupType Automatic
        Start-Service ssh-agent
        Get-Service ssh-agent
    }
    ssh-add "$env:userprofile\\.ssh\\id_rsa"
}