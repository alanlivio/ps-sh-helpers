# -- update --

function win_update() {
    log_msg "win_update"
    log_msg "> winget upgrade"
    winget upgrade --accept-package-agreements --accept-source-agreements --silent --scope user --all
    log_msg "> os upgrade"
    if (ps_is_running_as_sudo) { 
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
    } else {
        Write-Output "not running as sudo. do manually by run ms-settings:windowsupdate"
    }
}

# -- version --

function win_version() { (Get-CimInstance Win32_OperatingSystem).version }

function win_version_wsl_code_exts_info_for_github() {
    log_msg "alan_show_code_info_for_github"
    $command = "(Get-CimInstance Win32_OperatingSystem).version"
    Write-Host "> $command"
    Invoke-Expression $command
    $command = "wsl --version | Select -First 1"
    Write-Host "> $command"
    Invoke-Expression $command
    $command = "code --version | Select -First 1"
    Write-Host "> $command"
    Invoke-Expression $command
    $command = "(code --show-versions --list-extensions) -match 'latex'"
    Write-Host "> $command"
    Invoke-Expression $command

}

# -- admin --

function win_admin_user_enable() {
    net user administrator /active:yes
}

function win_admin_user_disable() {
    net user administrator /active:no
}

function win_admin_password_policy_disable() {
    log_msg "win_disable_password_policy"
    if (-not (ps_is_running_as_sudo)) { log_error "no admin. skipping disable password."; return }
    $tmpfile = New-TemporaryFile
    secedit /export /cfg $tmpfile /quiet # this call requires admin
    (Get-Content $tmpfile).Replace("PasswordComplexity = 1", "PasswordComplexity = 0").Replace("MaximumPasswordAge = 42", "MaximumPasswordAge = -1") | Out-File $tmpfile
    secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
    Remove-Item -Path $tmpfile
}

# -- install -- 

function win_install_miktex() {
    if (-Not(Get-Command miktex -errorAction SilentlyContinue)) {
        winget_install MiKTeX.MiKTeX
        win_path_reload
        miktex packages update
    }
}

function win_install_vlc () {
    param (
        [string]$version = "3.0.21",
        [string]$extractPath = "$env:userprofile\bin\"
    )
    $name = "VLC"
    $url = "https://www.mirrorservice.org/sites/videolan.org/vlc/$version/win32/vlc-$version-win32.zip"
    $zipPath = "$env:TEMP\vlc-$version-win32.zip"
    $tempExtractPath = Join-Path $env:TEMP "vlc_extract_temp"
    $exePath = Join-Path $extractPath "vlc-$version\vlc.exe"

    log_msg "Downloading $name $version"
    $webClient = New-Object System.Net.WebClient
    $webClient.DownloadFile($url, $zipPath)
    if (!(Test-Path $zipPath)) { log_error "Download failed"; return }

    if (!(Test-Path -Path $extractPath)) { New-Item -ItemType Directory -Path $extractPath | Out-Null }
    if (Test-Path $tempExtractPath) { Remove-Item -Recurse -Force $tempExtractPath }
    New-Item -ItemType Directory -Path $tempExtractPath | Out-Null

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    log_msg "Extracting vlc-$version-win32.zip to temp folder..."
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $tempExtractPath)
    log_msg "Copying vlc-$version-win32.zip to $tempExtractPath..."
    Copy-Item -Path "$tempExtractPath\*" -Destination $extractPath -Recurse -Force

    Remove-Item -Path $zipPath
    Remove-Item -Path $tempExtractPath -Recurse -Force

    win_startmenu_add_lnk_to_allapps $exePath
    log_msg "$exePath has been added to StartMenu."
}

function win_install_obs () {
    param (
        [string] $version = "30.2.3",
        [string] $extractPath = "$env:userprofile\bin\OBS"
    )
    $name = "OBS Studio"
    $url = "https://cdn-fastly.obsproject.com/downloads/OBS-Studio-$version-Windows.zip"
    $zipPath = "$env:TEMP\OBS-Studio-$version-Windows.zip"
    $tempExtractPath = Join-Path $env:TEMP "obs_extract_temp"
    $exePath = Join-Path $extractPath "bin\64bit\obs64.exe"

    log_msg "Downloading $name $version"
    $webClient = New-Object System.Net.WebClient
    $webClient.DownloadFile($url, $zipPath)
    if (!(Test-Path $zipPath)) { log_error "Download failed"; return }

    if (!(Test-Path -Path $extractPath)) { New-Item -ItemType Directory -Path $extractPath | Out-Null }
    if (Test-Path $tempExtractPath) { Remove-Item -Recurse -Force $tempExtractPath }
    New-Item -ItemType Directory -Path $tempExtractPath | Out-Null

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    log_msg "Extracting $name to temp folder..."
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $tempExtractPath)
    Copy-Item -Path "$tempExtractPath\*" -Destination $extractPath -Recurse -Force

    Remove-Item -Path $zipPath
    Remove-Item -Path $tempExtractPath -Recurse -Force

    win_startmenu_add_lnk_to_allapps $exePath
    log_msg "$exePath has been added to StartMenu."
}



function win_install_golang() {
    $version = "1.23.3"
    $name = "Go"
    $url = "https://golang.org/dl/go$version.windows-amd64.zip"
    $extractPath = "$env:userprofile\bin\go$version"
    $binPath = "$extractPath\bin"
    $zipPath = "$env:TEMP\go$version.zip"
    if (Test-Path $binPath) { return } # return if binPath already exists

    log_msg "Downloading $name $version"
    $webClient = New-Object System.Net.WebClient
    $webClient.DownloadFile($url, $zipPath)
    if (!(Test-Path -Path $extractPath)) {
        New-Item -ItemType Directory -Path $extractPath | Out-Null
    }
    
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    log_msg "Extracting $name to $extractPath"
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractPath)
    
    Remove-Item -Path $zipPath
    win_path_add("$binPath")
    log_msg "$name has been installed to $binPath and added to the PATH."
    win_path_reload
}

function win_install_nodejs_noadmin() {
    if (-Not(Get-Command node -errorAction SilentlyContinue)) {
        winget install Schniz.fnm
        $fnm = "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\Schniz.fnm_Microsoft.Winget.Source_8wekyb3d8bbwe\fnm.exe"
        & $fnm env --use-on-cd | Out-String | Invoke-Expression
        & $fnm use --install-if-missing 20
        win_path_add($env:FNM_MULTISHELL_PATH)
        win_path_reload
        node -v
        npm -v
    }
}

# -- winget --

$_WINGET_ARGS = "--accept-package-agreements --accept-source-agreements --scope user"
function winget_install() {
    param (
        [Parameter(Mandatory = $true)][string] $pkg,
        [Parameter(Mandatory = $false)][string] $version,
        [Parameter(Mandatory = $false)][string] $location,
        [Parameter(Mandatory = $false)][string] $override
    )
    
    winget list --accept-source-agreements -q $pkg | Out-Null
    if (-not $?) {
        $installArgs = @($_WINGET_ARGS -split ' ') + @('--id', $pkg)
        if ($version) { $installArgs += @('--version', $version) }
        if ($location) { $installArgs += @('--location', $location) }
        if ($override) { $installArgs += @('--override', $override) }
        winget install $installArgs
    }
}

function winget_uninstall() {
    param ([Parameter(Mandatory = $true)][string] $pkg)
    winget list --accept-source-agreements -q $pkg | Out-Null
    if ($?) {
        winget uninstall --id $pkg --silent 
    }
}

function winget_fix_installation() {
    gsudo {
        Remove-Item -Recurse "${env:localappdata}\Temp\WinGet\"  -Force -ErrorAction SilentlyContinue
        Remove-Item -Recurse "$env:LOCALAPPDATA\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe" -Force -ErrorAction SilentlyContinue
        Remove-Item -Recurse "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*"  -Force -ErrorAction SilentlyContinue
        winget source update
    }
}

# -- appx --

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
            Get-AppxPackage -User $env:username -Name $pkg | ForEach-Object { Add-AppxPackage -ea 0 -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" }
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

# -- env --

function win_env_add($name, $value) {
    [Environment]::SetEnvironmentVariable($name, $value, 'User')
}

function win_env_add_machine($name, $value) {
    if (Test-IsNotAdmin) { log_error "no admin. skipping."; return }
    [Environment]::SetEnvironmentVariable($name, $value, 'Machine')
}

function win_env_list() {
    [Environment]::GetEnvironmentVariables()
}

# -- path --

function win_path_reload() {
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", [System.EnvironmentVariableTarget]::Machine) + ";" + [System.Environment]::GetEnvironmentVariable("PATH", [System.EnvironmentVariableTarget]::User)
}

function win_path_add($addPath) {
    if (Test-Path $addPath) {
        $path = [Environment]::GetEnvironmentVariable('path', 'User')
        $regexAddPath = [regex]::Escape($addPath)
        $arrPath = $path -split ';' | Where-Object { $_ -notMatch "^$regexAddPath\\?" }
        $newpath = ($arrPath + $addPath) -join ';'
        [Environment]::SetEnvironmentVariable("path", $newpath, 'User')
    } else {
        Throw "'$addPath' is not a valid path."
    }
}

function win_path_list() {
    (Get-ChildItem Env:Path).Value -split ';'
}

# -- folder_open --

function folder_open_trash() {
    Start-Process explorer shell:recyclebinfolder
}

function folder_open_roaming_data() {
    Start-Process explorer "${env:appdata}"
}

function folder_open_local_programs() {
    Start-Process explorer "${env:localappdata}\Programs"
}

function folder_open_local_windows_apps() {
    Start-Process explorer "${env:localappdata}\Microsoft\WindowsApps"
}

function folder_open_local_winget_packages() {
    Start-Process explorer "${env:localappdata}\Microsoft\WinGet\Packages"
}

function folder_open_startmenu_programs() {
    Start-Process explorer "${env:userprofile}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"
}

# -- explorer --

function explorer_restart() {
    Stop-Process -Force -ErrorAction SilentlyContinue -ProcessName Explorer
}

function explorer_hide_home_dotfiles() {
    Get-ChildItem "${env:userprofile}\.*" | ForEach-Object { $_.Attributes += "Hidden" }
}

function explorer_restart() {
    log_msg "explorer_restart"
    taskkill /f /im explorer.exe | Out-Null
    Start-Process explorer.exe
}

function explorer_folder_use_pictures_icon {
    param ([string]$FolderPath)
    if (-Not (Test-Path $FolderPath)) {
        log_error "The folder '$FolderPath' does not exist." -ForegroundColor Red
        return
    }
    $DesktopIniPath = "$FolderPath\desktop.ini"
    @"
[.ShellClassInfo]
IconResource=%SystemRoot%\system32\imageres.dll,-113
IconFile=%SystemRoot%\system32\imageres.dll,-113
IconIndex=0
"@ | Set-Content -Path $DesktopIniPath -Encoding UTF8 -Force
    attrib +r "$FolderPath" /s /d > $null 2>&1
    attrib +h "$DesktopIniPath" > $null 2>&1
    log_msg "Successfully set the icon for '$FolderPath' to match the Pictures folder."
}

# -- hardlink --

function win_hardlink_create() {
    param (
        [Parameter(Mandatory = $true)]
        [string] $source,
        [Parameter(Mandatory = $true)]
        [string] $target
    )
    if (!(Test-Path "$target")) { 
        Throw "target=$target is not a valid"
    }
    if (Test-Path "$source") { 
        $hash1 = Get-FileHash "$source"
        $hash2 = Get-FileHash "$target"
        if ($hash1.Hash -ne $hash2.Hash) {
            log_msg "> remove old source=$source"
            Remove-Item -Force "$source"
        } else {
            return # it is same file
        }
    }
    log_msg "> creating hardlink source=$source target=$target"
    New-Item -ItemType Hardlink -Force -Path "$source" -Target "$target"
}

# -- wsl --

function wsl_call_with_profile() {
    bash  -i -c "$args"
}

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


function wsl_use_same_home() {
    log_msg "setup wsl to use same home"
    log_msg "target wsl is $(wsl_get_default)"
    if ((wsl echo '$HOME').Contains("Users")) {
        log_msg "WSL already use windows UserProfile as home."
        return
    }
    log_msg "terminate wsl"
    wsl_terminate
    $user_name = (wsl whoami)
    log_msg "change default dir to /mnt/c/Users/"
    wsl -u root skill -KILL -u $user_name
    wsl -u root usermod -d /mnt/c/Users/$env:UserName $user_name
    log_msg "create a link /home/user at /mnt/c/Users/user"
    wsl -u root rm -rf /home/$user_name
    wsl -u root ln -s /mnt/c/Users/$env:UserName /home/$user_name

}

function wsl_fix_metadata() {
    log_msg "wsl_fix_metadata"
    # https://docs.microsoft.com/en-us/windows/wsl/wsl-config
    # https://github.com/Microsoft/WSL/issues/3138
    # https://devblogs.microsoft.com/commandline/chmod-chown-wsl-improvements/
    log_msg "terminate wsl"
    wsl_terminate
    wsl -u root bash -c 'echo "[automount]" > /etc/wsl.conf'
    wsl -u root bash -c 'echo "options=\"metadata,umask=0022,fmask=11\"" >> /etc/wsl.conf'
}

# -- office --

function win_office_disable_warn_local_link() {
    # https://superuser.com/questions/1307645/how-to-disable-hyperlink-security-notice-in-onenote-2016
    $reg = "HKCU:\Software\Microsoft\Office\16.0\Common\Security"
    New-Item -Path $reg -Force | Out-Null
    Set-ItemProperty -Path $reg -Name "DisableHyperlinkWarning" -Value 1 -Type Dword -Force
}

# -- system --

function win_system_image_scan_cleanup() {
    if (Test-IsNotAdmin) { log_error "no admin. skipping."; return }
    cmd.exe /c 'sfc /scannow'
    dism.exe /Online /Cleanup-image /Restorehealth    
    dism /Online /Cleanup-Image /RestoreHealth
}

function win_system_policy_reset() {
    if (Test-IsNotAdmin) { log_error "no admin. skipping."; return }
    cmd.exe /C 'RD /S /Q %WinDir%\System32\GroupPolicyUsers '
    cmd.exe /C 'RD /S /Q %WinDir%\System32\GroupPolicy '
    gpupdate.exe /force
}


function win_system_enable_ssh_agent() {
    if (Test-IsNotAdmin) { log_error "no admin. skipping."; return }
    Set-Service ssh-agent -StartupType Automatic
    Start-Service ssh-agent
    Get-Service ssh-agent
    ssh-add "$env:userprofile\\.ssh\\id_rsa"
}

# -- startmenu/desktop --

function win_onedrive_make_folder_avaliable() {
    param(
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Full path to the OneDrive folder.")]
        [ValidateScript({
                if (Test-Path $_ -PathType Container) { return $true }
                else { throw "Path not found or is not a directory: '$_'" }
            })]
        [string]$Path
    )
    log_msg "INFO" "Executing: attrib  for '$Path'."
    try {
        # Use attrib.exe: -U (Unpin), +P (Pin), /s (Subdirs), /d (Process Dirs too)
        $commandArgs = "-U +P ""$Path"" /s /d"
        attrib $commandArgs
        if ($LASTEXITCODE -eq 0) {
            log_msg  "attrib command successful for '$Path'. OneDrive will sync."
        } else {
            log_error "attrib command for '$Path' finished with exit code $LASTEXITCODE."
        }
    } catch {
        log_error "Failed attribprocessing '$Path': $($_.Exception.Message)"
    }
}


function win_onedrive_reset() {
    & "C:\Program Files\Microsoft OneDrive\onedrive.exe" /reset
}

# -- startmenu/desktop --

function win_startmenu_add_lnk_to_allapps {
    param (
        [Parameter(Mandatory = $true)][string]$exePath  # Path to the .exe file
    )
    if (-not (Test-Path $exePath)) {
        log_error "The specified executable path does not exist: $exePath"
        return
    }
    $shortcutName = [System.IO.Path]::GetFileNameWithoutExtension($exePath) + ".lnk"
    $startMenuFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs"
    if (-not (Test-Path $startMenuFolder)) {
        log_error "The Start Menu folder does not exist: $startMenuFolder"
        return
    }
    $shortcutPath = Join-Path -Path $startMenuFolder -ChildPath $shortcutName
    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $exePath
        $shortcut.WorkingDirectory = (Split-Path -Parent $exePath)
        $shortcut.Description = "Shortcut to $(Split-Path -Leaf $exePath)"
        $shortcut.Save()
        log_msg "Shortcut successfully created: $shortcutPath"
    } catch {
        log_error "An error occurred while creating the shortcut: $_"
    }
}

function win_desktop_as_slideshow_from_folder() {
    param ([string]$folderPath )
    if (-Not (Test-Path $folderPath)) {
        log_error "The folder '$folderPath' does not exist. Please provide a valid folder." -ForegroundColor Red
        exit 1
    }
    # Enable Slideshow mode
    $regPath = "HKCU:\Control Panel\Personalization\Desktop Slideshow"
    $wallpaperPathReg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers"
    if (-Not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $wallpaperPathReg -Name SlideshowEnabled -Value 1
    Set-ItemProperty -Path $wallpaperPathReg -Name SlideshowSource -Value $folderPath
    $intervalMs = 600000  # 10 minutes
    Set-ItemProperty -Path $regPath -Name Interval -Value $intervalMs -Type DWord
    Set-ItemProperty -Path $regPath -Name Shuffle -Value 1 -Type DWord  # Set Shuffle Mode (1 = Enabled, 0 = Disabled)
    
    # Refresh the desktop settings
    RUNDLL32.EXE USER32.DLL, UpdatePerUserSystemParameters
}

# -- win_edge --

function win_edge_disable_edge_ctrl_shift_c() {
    log_msg "win_edge_disable_edge_ctrl_shift_c"
    if (Test-IsNotAdmin) { log_error "no admin. skipping."; return }
    $reg_edge_pol = "HKCU:\Software\Policies\Microsoft\Edge"
    New-Item -Path $reg_edge_pol -Force | Out-Null
    if (-not (Get-ItemPropertyValue -Path $reg_edge_pol -Name 'ConfigureKeyboardShortcuts')) {
        Set-ItemProperty -Path $reg_edge_pol -Name 'ConfigureKeyboardShortcuts' -Value '{"disabled": ["dev_tools_elements"]}'
        gpupdate.exe /force
    }
}

# -- win_clutter --

function win_clutter_use_dark_no_transparency() {
    log_msg "win_clutter_use_dark_no_transparency"
    $reg_personalize = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    Set-ItemProperty -Path $reg_personalize -Name "AppsUseLightTheme" -Value 0 -Type Dword -Force 
    Set-ItemProperty -Path $reg_personalize -Name "SystemUsesLightTheme" -Value 0 -Type Dword -Force 
    Set-ItemProperty -Path $reg_personalize -Name "EnableTransparency" -Value 0 -Type Dword -Force 
    Set-ItemProperty -Path $reg_personalize -Name "ColorPrevalence" -Value 0 -Type Dword -Force 
    $reg_accent = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent"
    $AccentPalette = "cc,cc,cc,00,ae,ae,ae,00,92,92,92,00,76,76,76,00,4f,4f,4f,00,37,37,37,00,26,26,26,00,d1,34,38,00"
    $hexified = $AccentPalette.Split(',') | ForEach-Object { "0x$_" }
    Set-ItemProperty -Path $reg_accent -Name "AccentPalette" -Value ([byte[]]$hexified) -Type Binary
    Set-ItemProperty -Path $reg_accent -Name "AccentColor" -Value 0xff000000 -Type Dword -Force
    Set-ItemProperty -Path $reg_accent -Name "AccentColorMenu" -Value 0xff767676 -Type Dword -Force
    Set-ItemProperty -Path $reg_accent -Name "StartColorMenu" -Value 0xff4f4f4f -Type Dword -Force
}

function win_clutter_remove_all_and_explorer_restart() {
    win_clutter_remove_3_and_4_fingers_gestures
    win_clutter_remove_bell_sounds
    win_clutter_remove_desktop_icons
    win_clutter_remove_explorer
    win_clutter_remove_old_unused_folders
    win_clutter_remove_osapps_unused
    win_clutter_remove_shortcuts_unused
    win_clutter_remove_taskbar
    win_clutter_remove_web_search_and_widgets
    win_clutter_remove_xbox
    explorer_restart
}

function win_clutter_remove_old_unused_folders() {
    $paths = @(
        "${env:userprofile}\Cookies"
        "${env:userprofile}\Local Settings"
        "${env:userprofile}\My Documents"
        "${env:userprofile}\Start Menu"
        "${env:userprofile}\PrintHood"
        "${env:userprofile}\Recent"
        "${env:userprofile}\SendTo"
        "${env:userprofile}\NetHood"
        "${env:userprofile}\Templates"
    )
    $paths | ForEach-Object { 
        if (Test-Path -Path "$_") {
            Remove-Item $_
        }
    }
}

function win_clutter_remove_desktop_icons() {
    $Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-ItemProperty -Path $Path -Name "HideIcons" -Value 1
}

function win_clutter_remove_osapps_unused() {
    log_msg "win_clutter_remove_osapps_unused"
    winget_uninstall "Mail and Calendar"
    winget_uninstall "Microsoft Sticky Notes"
    winget_uninstall "Microsoft Clipchamp"
    winget_uninstall "Solitaire & Casual Games"
    winget_uninstall "News"
    winget_uninstall "Windows Maps"
    winget_uninstall "Microsoft People"
    winget_uninstall "Films & TV"
    winget_uninstall "Power Automate"
}

function win_clutter_remove_3_and_4_fingers_gestures() {
    log_msg "win_clutter_remove_3_and_4_fingers_gestures"
    $reg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\PrecisionTouchPad"
    Set-ItemProperty -Path $reg -Name "FourFingerDown" -Value 0 -Type Dword
    Set-ItemProperty -Path $reg -Name "FourFingerLeft" -Value 0 -Type Dword
    Set-ItemProperty -Path $reg -Name "FourFingerRight" -Value 0 -Type Dword
    Set-ItemProperty -Path $reg -Name "FourFingerUp" -Value 0 -Type Dword
    Set-ItemProperty -Path $reg -Name "FourFingerTapEnabled" -Value 0 -Type Dword
    Set-ItemProperty -Path $reg -Name "ThreeFingerDown" -Value 0 -Type Dword
    Set-ItemProperty -Path $reg -Name "ThreeFingerLeft" -Value 0 -Type Dword
    Set-ItemProperty -Path $reg -Name "ThreeFingerRight" -Value 0 -Type Dword
    Set-ItemProperty -Path $reg -Name "ThreeFingerTapEnabled" -Value 0 -Type Dword
    Set-ItemProperty -Path $reg -Name "ThreeFingerUp" -Value 0 -Type Dword
}

function win_clutter_remove_shortcuts_unused() {
    log_msg "win_clutter_remove_shortcuts_unused"
    
    # "disable AutoRotation shorcuts"
    $igf = "HKCU:\Software\Intel\Display\Igfxcui"
    New-Item -Path $igf -Force | Out-Null
    Set-ItemProperty -Path $igf -Name "HotKeys" -Value 'Enable'

    # "disable language shorcuts"
    $reg_key_toggle = "HKCU:\Keyboard Layout\Toggle"
    Set-ItemProperty -Path $reg_key_toggle -Name "HotKey" -Value '3' -Type String
    Set-ItemProperty -Path $reg_key_toggle -Name "Language Hotkey" -Value '3' -Type String
    Set-ItemProperty -Path $reg_key_toggle -Name "Layout Hotkey" -Value '3' -Type String

    # "disable acessibility shorcuts"
    $reg_acess = "HKCU:\Control Panel\Accessibility"
    Set-ItemProperty -Path "$reg_acess\ToggleKeys" -Name "Flags" -Value '58' -Type String
    Set-ItemProperty -Path "$reg_acess\StickyKeys" -Name "Flags" -Value '26' -Type String
    New-Item -Path "$reg_acess\Keyboard Response" -Force | Out-Null
    Set-ItemProperty -Path "$reg_acess\Keyboard Response" -Name "Flags" -Value '122' -Type String
}

function win_clutter_remove_bell_sounds() {
    log_msg "win_clutter_remove_bell_sounds"
    Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\" "(Default)" -Value ".None"
    Get-ChildItem -Path 'HKCU:\AppEvents\Schemes\Apps' | Get-ChildItem | Get-ChildItem | Where-Object { $_.PSChildName -eq '.Current' } | Set-ItemProperty -Name '(Default)' -Value '' 
}

function win_clutter_remove_web_search_and_widgets() {
    log_msg "win_clutter_remove_web_search_and_widgets"
    # win 11
    # https://www.tomshardware.com/how-to/disable-windows-web-search
    winget list --accept-source-agreements -q "MicrosoftWindows.Client.WebExperience_cw5n1h2txyew" | Out-Null
    if ($?) { winget.exe uninstall MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy }
    # win 10
    # https://www.bennetrichter.de/en/tutorials/windows-10-disable-web-search/
    $reg_search = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
    Set-ItemProperty -Path "$reg_search" -Name 'BingSearchEnabled' -Value 0 -Type Dword
    $reg_search2 = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings'
    Set-ItemProperty -Path "$reg_search2" -Name 'IsDynamicSearchBoxEnabled' -Value 0 -Type Dword
}

function win_clutter_remove_explorer() {
    log_msg "win_clutter_remove_explorer"
    $reg_explorer = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
    # setup folder listing
    Set-ItemProperty -Path $reg_explorer -Name ShowFrequent -Value 0 -Type Dword
    Set-ItemProperty -Path $reg_explorer -Name ShowRecent -Value 0 -Type Dword
    Set-ItemProperty -Path $reg_explorer -Name ShowRecommendations -Value 0 -Type Dword
    Set-ItemProperty -Path $reg_explorer -Name HideFileExt -Value 0 -Type Dword
    # remove grouping listing
    # https://answers.microsoft.com/en-us/windows/forum/all/completely-disable-file-grouping-always-everywhere/ac31a227-f585-4b0a-ab2e-a557828eaec5
    $key = 'HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell' 
    Remove-Item -Path "$key\BagMRU"  -Force -ErrorAction SilentlyContinue
}

function win_clutter_remove_taskbar() {
    log_msg "win_clutter_remove_taskbar"
    $reg_explorer_adv = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    
    # taskbar
    # https://www.askvg.com/disable-or-remove-extra-icons-and-buttons-from-windows-11-taskbar
    Set-ItemProperty -Path $reg_explorer_adv -Name ShowTaskViewButton -Value 0 -Type Dword
    # Set-ItemProperty -Path $reg_explorer_adv -Name TaskbarDa -Value 0 -Type Dword
    Set-ItemProperty -Path $reg_explorer_adv -Name TaskbarMn -Value 0 -Type Dword
    Set-ItemProperty -Path $reg_explorer_adv -Name ShowCopilotButton -Value 0 -Type Dword
    Set-ItemProperty -Path $reg_explorer_adv -Name UseCompactMode -Value 1 -Type Dword
    Set-ItemProperty -Path $reg_explorer_adv -Name ShowStatusBar -Value 1 -Type Dword
    Set-ItemProperty -Path $reg_explorer_adv -Name TaskbarAI -Value 0 -Type Dword
    Set-ItemProperty -Path $reg_explorer_adv -Name TaskbarBadges -Value 0 -Type Dword
    Set-ItemProperty -Path $reg_explorer_adv -Name TaskbarAnimations -Value 0 -Type Dword

    # multitasking
    # https://www.itechtics.com/disable-edge-tabs-alt-tab
    Set-ItemProperty -Path $reg_explorer_adv -Name MultiTaskingAltTabFilter -Value 3 -Type Dword
    # https://superuser.com/questions/1516878/how-to-disable-windows-snap-assist-via-command-line
    Set-ItemProperty -Path $reg_explorer_adv -Name SnapAssist -Value 0 -Type Dword
    
    # search
    $reg_search = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
    Set-ItemProperty -Path $reg_search -Name SearchBoxTaskbarMode -Value 0 -Type Dword
}

function win_clutter_remove_copilot() {
    # https://winaero.com/disable-windows-copilot/
    sudo {
        $reg_explorer_pol = "HKCU:\Software\Policies\Microsoft\Windows"
        New-Item -Path "$reg_explorer_pol\WindowsCopilot" -Force | Out-Null
        Set-ItemProperty -Path "$reg_explorer_pol\WindowsCopilot" -Name 'TurnOffWindowsCopilot' -Value 1 -Type Dword
    }
}

function win_clutter_remove_xbox() {
    log_msg "win_clutter_remove_xbox"
    # https://www.makeuseof.com/windows-new-app-ms-gamingoverlay-error/

    $reg_game_dvr = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"
    Set-ItemProperty -Path $reg_game_dvr -Name AppCaptureEnabled -Value 0 -Type Dword
    Set-ItemProperty -Path $reg_game_dvr -Name HistoricalCaptureEnabled -Value 0 -Type Dword
    $reg_game_store = "HKCU:\System\GameConfigStore"
    Set-ItemProperty -Path $reg_game_store -Name GameDVR_Enabled -Value 0 -Type Dword

    winget_uninstall 9MV0B5HZVK9Z
    winget_uninstall Microsoft.Xbox.TCUI_8wekyb3d8bbwe
    winget_uninstall Microsoft.XboxApp_8wekyb3d8bbwe
    winget_uninstall Microsoft.XboxGameOverlay_8wekyb3d8bbwe
    winget_uninstall Microsoft.XboxGamingOverlay_8wekyb3d8bbwe
    winget_uninstall Microsoft.XboxIdentityProvider_8wekyb3d8bbwe
    winget_uninstall Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe
}