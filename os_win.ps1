# sudo calls on here require https://learn.microsoft.com/en-us/windows/sudo/ or https://github.com/gerardog/gsudo

# -- essentials --

function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }

function win_update() {
    log_msg "winget upgrade all"
    winget upgrade --accept-package-agreements --accept-source-agreements --silent --all
    log_msg "win os upgrade"
    sudo {
        if (-Not(Get-Command Install-WindowsUpdate -errorAction SilentlyContinue)) {
            Set-PSRepository PSGallery -InstallationPolicy Trusted
            Install-Module -Name PSWindowsUpdate -Confirm:$false
            Add-WUServiceManager -MicrosoftUpdate -Confirm:$false | Out-Null
        }
        $(Install-WindowsUpdate -AcceptAll -IgnoreReboot) | Where-Object {
            if ($_ -is [string]) {
                $_.Split('', [System.StringSplitOptions]::RemoveEmptyEntries)
            }
        }
    }
}

function winget_install() {
    winget list -q $Args | Out-Null
    if (-not $?) {
        winget install --accept-package-agreements --accept-source-agreements --silent "$Args"
    }
}

function ps_profile_reload() {
    @(
        $profile.AllUsersAllHosts,
        $profile.AllUsersCurrentHost,
        $profile.CurrentUserAllHosts,
        $profile.CurrentUserCurrentHost
    ) | % {
        if (Test-Path $_) {
            echo "loading $_"
            . $_
        }
    }
}

function ps_show_function($name) {
    Get-Content Function:\$name
}

function win_hlink_create($path, $target) {
    sudo New-Item -ItemType SymbolicLink -Force -Path $path -Target $target
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
    sudo { dism /Online /Cleanup-Image /RestoreHealth }
}

function win_policy_reset() {
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
    sudo { Get-AppxPackage -User $env:username | ForEach-Object { Write-Output $_.Name } }
}

function win_appx_install() {
    $pkgs_to_install = ""
    foreach ($name in $args) {
        if ( !(Get-AppxPackage -User $env:username -Name $name)) {
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
    # microsoft
    $pkgs = @(
        'Clipchamp.Clipchamp'
        'Microsoft.3DBuilder'
        'Microsoft.Appconnector'
        'Microsoft.BingNews'
        'Microsoft.BingSports'
        'Microsoft.BingWeather'
        'Microsoft.CommsPhone'
        'Microsoft.ConnectivityStore'
        'Microsoft.Microsoft3DViewer'
        'Microsoft.MicrosoftSolitaireCollection'
        'Microsoft.MicrosoftStickyNotes'
        'Microsoft.MixedReality.Portal'
        'Microsoft.OneConnect'
        'Microsoft.Paint'
        'Microsoft.People'
        'Microsoft.PowerAutomateDesktop'
        'Microsoft.Print3D'
        'Microsoft.SkypeApp'
        'Microsoft.StorePurchaseApp'
        'Microsoft.Wallet'
        'Microsoft.WindowsMaps'
        'Microsoft.YourPhone'
        'Microsoft.ZuneMusic'
        'SpotifyAB.SpotifyMusic'
        'NVIDIACorp.NVIDIAControlPanel'
        'Microsoft.Windows.DevHome'
    )
    win_appx_uninstall @pkgs
}

function win_disable_password_policy() {
    sudo {
        $tmpfile = New-TemporaryFile
        secedit /export /cfg $tmpfile /quiet
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
    sudo {
        $reg_acess = "HKCU:\Control Panel\Accessibility"
        Set-ItemProperty -Path "$reg_acess\ToggleKeys" -Name "Flags" -Value '58' -Type 'DWORD'
        New-Item -Path  "$reg_acess\Keyboard Response" -Force | Out-Null
        Set-ItemProperty -Path "$reg_acess\Keyboard Response" -Name "Flags" -Value '122' -Type 'DWORD'
    }

    # explorer restart
    Stop-Process -ProcessName explorer -ea 0 | Out-Null
}

function win_disable_sounds() {
    log_msg "win_disable_sounds"
    Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\" "(Default)" -Value ".None"
    $status = (Get-Service -name beep).Status
    if ( $status -eq "Running" ) {
        sudo {
            Stop-Service beep
            Set-Service beep -StartupType disabled
        }
    }
}

function win_disable_web_search_and_widgets() {
    # win 10
    # https://www.bennetrichter.de/en/tutorials/windows-10-disable-web-search/
    log_msg "win_disable_web_search_and_widgets"
    $reg_search = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
    Set-ItemProperty -Path "$reg_search" -Name 'BingSearchEnabled' -Value '0' -Type 'DWORD'
    $reg_search2 = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'
    Set-ItemProperty -Path "$reg_search2" -Name 'IsDynamicSearchBoxEnabled' -Value '0' -Type 'DWORD'

    # win 11
    # https://www.tomshardware.com/how-to/disable-windows-web-search
    sudo {
        $reg_explorer_pols = "HKCU:\Software\Policies\Microsoft\Windows\Explorer"
        New-Item -Path $reg_explorer_pols -Force | Out-Null
        Set-ItemProperty -Path $reg_explorer_pols -Name 'DisableSearchBoxSuggestions' -Value '1' -Type 'DWORD'
    }
    winget list -q "MicrosoftWindows.Client.WebExperience_cw5n1h2txyew" | Out-Null
    if ($?) { winget.exe uninstall MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy }
}

function win_disable_edge_ctrl_shift_c() {
    log_msg "win_disable_edge_ctrl_shift_c"
    sudo {
        $reg_edge_pol = "HKCU:\Software\Policies\Microsoft\Edge"
        if (-not (Get-ItemPropertyValue -Path $reg_edge_pol -Name 'ConfigureKeyboardShortcuts')) {
            New-Item -Path $reg_edge_pol -Force | Out-Null
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
    
    # setup taskbar startmenu
    # https://www.askvg.com/disable-or-remove-extra-icons-and-buttons-from-windows-11-taskbar
    Set-ItemProperty -Path $reg_explorer_adv -Name ShowTaskViewButton -Value '0' -Type 'DWORD'
    Set-ItemProperty -Path $reg_explorer_adv -Name TaskbarDa -Value '0' -Type 'DWORD'
    Set-ItemProperty -Path $reg_explorer_adv -Name TaskbarMn -Value '0' -Type 'DWORD'
    Set-ItemProperty -Path $reg_explorer_adv -Name TaskbarAI -Value '0' -Type 'DWORD'
    Set-ItemProperty -Path $reg_explorer_adv -Name TaskbarBadges -Value '0' -Type 'DWORD'
    Set-ItemProperty -Path $reg_explorer_adv -Name TaskbarAnimations -Value '0' -Type 'DWORD'

    # setup clean multitasking
    # https://www.itechtics.com/disable-edge-tabs-alt-tab
    Set-ItemProperty -Path $reg_explorer_adv -Name MultiTaskingAltTabFilter -Value '3' -Type 'DWORD'
    # https://superuser.com/questions/1516878/how-to-disable-windows-snap-assist-via-command-line
    Set-ItemProperty -Path $reg_explorer_adv -Name SnapAssist -Value '0' -Type 'DWORD'
    
    # setup search
    $reg_search = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
    Set-ItemProperty -Path $reg_search -Name SearchBoxTaskbarMode -Value '0' -Type 'DWORD'
}

function win_disable_gaming_clutter() {
    log_msg "win_disable_gaming_clutter"
    # https://www.makeuseof.com/windows-new-app-ms-gamingoverlay-error/

    $reg_game_dvr = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"
    Set-ItemProperty -Path $reg_game_dvr -Name AppCaptureEnabled -Value '0' -Type 'DWORD'
    Set-ItemProperty -Path $reg_game_dvr -Name HistoricalCaptureEnabled -Value '0' -Type 'DWORD'
    $reg_game_store = "HKCU:\System\GameConfigStore"
    Set-ItemProperty -Path $reg_game_store -Name GameDVR_Enabled -Value '0' -Type 'DWORD'

    $pkgs = @(
        'Microsoft.Xbox.TCUI'
        'Microsoft.XboxApp'
        'Microsoft.XboxGameOverlay'
        'Microsoft.XboxGamingOverlay'
        'Microsoft.XboxIdentityProvider'
        'Microsoft.XboxSpeechToTextOverlay'
    )
    win_appx_uninstall @pkgs
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
    sudo { dism /online /enable-feature /featurename:Microsoft-Hyper-V -All /LimitAccess /ALL }
}


function win_ssh_agent_and_add_id_rsa() {
    sudo {
        Set-Service ssh-agent -StartupType Automatic
        Start-Service ssh-agent
        Get-Service ssh-agent
    }
    ssh-add "$env:userprofile\\.ssh\\id_rsa"
}