# -- os_upgrade --

function win_os_upgrade() {
    log_msg "win_os_upgrade"
    if (-not (ps_is_running_as_sudo)) { log_msg "not running as admin. skipping"; return }
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

# -- admin --

function win_admin_user_enable() {
    net user administrator /active:yes
}

function win_admin_user_disable() {
    net user administrator /active:no
}

function win_admin_password_policy_disable() {
    log_msg "win_disable_password_policy"

    if (-not (ps_is_running_as_sudo)) { log_msg "not running as admin. skipping"; return }
    $tmpfile = New-TemporaryFile
    secedit /export /cfg $tmpfile /quiet # this call requires admin
    (Get-Content $tmpfile).Replace("PasswordComplexity = 1", "PasswordComplexity = 0").Replace("MaximumPasswordAge = 42", "MaximumPasswordAge = -1") | Out-File $tmpfile
    secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
    Remove-Item -Path $tmpfile
}

# -- install -- 

function win_install_exe_from_zip() {
    # if the basename of extractPath exist inside extracted Path so get from inside that folder
    # For example: win_install_exe_from_zip ""...\vlc-3.0.21.zip" "...\bin\vlc-3.0.21" "vlc.exe" 
    # there is a vlc-3.0.21 folder inside vlc-3.0.21-win64.zip
    # so the content of that nested folder is used
    
    param(
        [Parameter(Mandatory = $true)][string]$url_or_path_to_zip,
        [Parameter(Mandatory = $true)][string]$extractPath, # it should has a name if the zip has no main folder
        [Parameter(Mandatory = $true)][string]$exePathOnZip # exe inside the zip
    )
    $exePath = Join-Path $extractPath $exePathOnZip
    $sourceZipFilePath = ""
    $downloadedFileCleanup = $false
    if (!(Test-Path -Path $exePath)) {
        # download
        if ($url_or_path_to_zip.StartsWith("http://") -or $url_or_path_to_zip.StartsWith("https://")) {
            $uri = New-Object System.Uri($url_or_path_to_zip)
            $derivedZipFileName = [System.IO.Path]::GetFileName($uri.LocalPath)
            $randomDownloadFileName = [System.Guid]::NewGuid().ToString().Replace("-", "") + "-" + $derivedZipFileName
            $downloadPath = Join-Path $env:TEMP $randomDownloadFileName
            if (Test-Path $downloadPath) { Remove-Item $downloadPath -Force }

            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($url_or_path_to_zip, $downloadPath)
            if (!(Test-Path $downloadPath)) { log_error "download failed"; return }
            $sourceZipFilePath = $downloadPath
            $downloadedFileCleanup = $true
        } else {
            $sourceZipFilePath = $url_or_path_to_zip
        }
        # extract
        $randomExtractFolderName = [System.Guid]::NewGuid().ToString().Replace("-", "")
        $tempExtractPath = Join-Path $env:TEMP $randomExtractFolderName
        if (!(Test-Path -Path $extractPath)) { New-Item -ItemType Directory -Path $extractPath | Out-Null }
        if (Test-Path $tempExtractPath) { Remove-Item -Recurse -Force $tempExtractPath }
        New-Item -ItemType Directory -Path $tempExtractPath | Out-Null
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        try { 
            [System.IO.Compression.ZipFile]::ExtractToDirectory($sourceZipFilePath, $tempExtractPath) 
        } catch { log_error "extract failed"; return }
        # if the basename of extractPath exist inside extracted Path so get from inside that folder
        $extractPathBasename = (Split-Path -Path $extractPath -Leaf)
        if (Test-Path (Join-Path $tempExtractPath $extractPathBasename)) {
            Copy-Item -Path "$tempExtractPath\$extractPathBasename\*" -Destination $extractPath -Recurse -Force
        } else {
            Copy-Item -Path "$tempExtractPath\*" -Destination $extractPath -Recurse -Force
        }
        # cleanup
        if ($downloadedFileCleanup) { Remove-Item -Path $sourceZipFilePath -Force }
        Remove-Item -Path $tempExtractPath -Recurse -Force
        # add start menu
        log_msg "add $exePath to StartMenu."
        win_startmenu_add_lnk_to_allapps $exePath
    }
}

function win_install_vlc() {
    $vlcLatestWin64Url = "https://get.videolan.org/vlc/last/win64/"
    $webRequest = Invoke-WebRequest -Uri $vlcLatestWin64Url -Method Get -ErrorAction Stop
    $vlcZipLink = $webRequest.Links | Where-Object { $_.href -like "*win64.zip" } | Select-Object -First 1
    if (-not ($vlcZipLink)) { log_error "Download failed"; return }
    $vlcZip = $vlcZipLink.href
    $url = "https://get.videolan.org/vlc/last/win64/$vlcZip"
    $name = $vlcZip -replace '-win64\.zip$'
    win_install_exe_from_zip $url "$env:userprofile\bin\$name" "vlc.exe"
}

function win_install_obs() {
    $apiUrl = "https://api.github.com/repos/obsproject/obs-studio/releases/latest"
    $response = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers @{"Accept" = "application/vnd.github.v3+json" }
    if (-not ($response)) { log_error "Download failed"; return }
    $version = $response.tag_name
    $url = "https://github.com/obsproject/obs-studio/releases/download/$version/OBS-Studio-$version-Windows.zip"
    win_install_exe_from_zip $url "$env:userprofile\bin\OBS" "bin\64bit\obs64.exe"
}

function win_install_gh() {
    $apiUrl = "https://api.github.com/repos/cli/cli/releases/latest"
    $response = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers @{"Accept" = "application/vnd.github.v3+json" }
    if (-not ($response)) { log_error "Download failed"; return }
    $version = $response.tag_name.Substring(1)
    $url = "https://github.com/cli/cli/releases/download/v$version/gh_${version}_windows_amd64.zip" 
    win_install_exe_from_zip $url "$env:userprofile\bin\gh" "bin\gh.exe"
    win_path_add "$env:userprofile\bin\gh\bin"
}

function win_install_vim() {
    winget_install vim.vim
    win_path_add "$env:LOCALAPPDATA\Programs\vim\vim91"
}

function win_install_tor() {
    if (!(Test-Path "$env:LOCALAPPDATA\Programs\TorBrowser")) { 
        winget install TorProject.TorBrowser --location="$env:LOCALAPPDATA\Programs\TorBrowser" 
        win_startmenu_add_lnk_to_allapps "$env:LOCALAPPDATA\Programs\TorBrowser\Browser\firefox.exe" TorBrowser
    }
}

# -- winget --

function winget_upgrade() {
    winget upgrade --all --accept-package-agreements --accept-source-agreements --silent --scope user

}

function winget_install() {
    winget list --accept-source-agreements -q $args[0] | Out-Null # first arg is the id
    if (-not($?)) {
        winget install "$args" --accept-package-agreements --accept-source-agreements --silent
    }
}

function winget_uninstall() {
    param ([Parameter(Mandatory = $true)][string] $pkg)
    winget list --accept-source-agreements -q $pkg | Out-Null
    if ($?) {
        winget uninstall $pkg
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
    attrib +r "$FolderPath" /s /d > $null
    attrib +h "$DesktopIniPath" > $null
    log_msg "Successfully set the icon for '$FolderPath' to match the Pictures folder."
}

function explorer_hide_home_dotfiles() {
    Get-ChildItem "${env:userprofile}\.*" | ForEach-Object { 
        if (Test-Path -Path "$_") {
            # Get-Item should use -Force if already hidden
            if (-Not(Get-Item "$_" -Force).attributes.ToString().Contains('Hidden')) {
                (Get-Item("$_") -Force).Attributes += "Hidden"  
            }
        }
    }
}

# -- hardlink --

function win_hardlink_create() {
    param (
        [Parameter(Mandatory = $true)]
        [string] $source,
        [Parameter(Mandatory = $true)]
        [string] $target
    )
    $target = Resolve-Path $target
    if (!(Test-Path "$target")) { log_error "hardlink target $target is not a valid"; return }
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
    log_msg "> creating HardLink source=$source target=$target"
    New-Item -ItemType Hardlink -Force -Path "$source" -Target "$target"
}

function win_symboliclink_create() {
    param (
        [Parameter(Mandatory = $true)]
        [string] $source,
        [Parameter(Mandatory = $true)]
        [string] $target
    )
    $target = Resolve-Path $target
    if (!(Test-Path "$target")) { log_error "SymbolicLink target $target is not a valid"; return }
    log_msg "> creating SymbolicLink source=$source target=$target"
    New-Item -ItemType SymbolicLink -Force -Path "$source" -Target "$target"
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

function win_system_disable_power_sleep_buttons() {
    powercfg -setacvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 0
}

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

# -- onedrive --

function win_onedrive_make_folder_avaliable() {
    param ([string]$Path = (Get-Location).Path)
    log_msg "win_onedrive_make_folder_avaliable $Path"
    $files = Get-ChildItem -Path $Path -File -Recurse -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        # Check if the file is a reparse point (i.e., online-only OneDrive file)
        if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq [System.IO.FileAttributes]::ReparsePoint) {
            $fs = [System.IO.FileStream]::new($file.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            $null = $fs.Read([byte[]]::new(1024), 0, 1024); $fs.Close(); $fs.Dispose()
        }
    }
}


function win_onedrive_reset() {
    & "C:\Program Files\Microsoft OneDrive\onedrive.exe" /reset
}

# -- startmenu/desktop --

function win_startmenu_add_lnk_to_allapps {
    param (
        [Parameter(Mandatory = $true)][string]$exePath,                # Path to the .exe file
        [Parameter(Mandatory = $false)][string]$shortcutName           # Optional shortcut name
    )

    if (-not (Test-Path $exePath)) {
        log_error "The specified executable path does not exist: $exePath"
        return
    }

    if (-not $shortcutName) {
        $shortcutName = [System.IO.Path]::GetFileNameWithoutExtension($exePath) + ".lnk"
    } elseif (-not $shortcutName.EndsWith(".lnk")) {
        $shortcutName += ".lnk"
    }

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

function win_declutter_all_and_explorer_restart() {
    win_declutter_ui
    win_declutter_home_folders
    win_declutter_osapps
    win_declutter_3_and_4_fingers_gestures
    win_declutter_unused_keyboard_shortcuts
    win_declutter_bell_sounds
    win_declutter_explorer_listing_files
    win_declutter_web_search_and_widgets
    win_declutter_taskbar
    win_declutter_xbox
    win_office_disable_warn_local_link
    explorer_restart
}

function win_declutter_ui() {
    log_msg "win_declutter_ui"
    # dark enabled and transparent disabled
    $reg_personalize = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    Set-ItemProperty -Path $reg_personalize -Name "AppsUseLightTheme" -Value 0 -Type Dword -Force 
    Set-ItemProperty -Path $reg_personalize -Name "SystemUsesLightTheme" -Value 0 -Type Dword -Force 
    Set-ItemProperty -Path $reg_personalize -Name "EnableTransparency" -Value 0 -Type Dword -Force 
    Set-ItemProperty -Path $reg_personalize -Name "ColorPrevalence" -Value 0 -Type Dword -Force 
    # gray accent color
    $reg_accent = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent"
    $accent_palette = "cc,cc,cc,00,ae,ae,ae,00,92,92,92,00,76,76,76,00,4f,4f,4f,00,37,37,37,00,26,26,26,00,d1,34,38,00"
    $hexified = $accent_palette.Split(',') | ForEach-Object { "0x$_" }
    Set-ItemProperty -Path $reg_accent -Name "AccentPalette" -Value ([byte[]]$hexified) -Type Binary
    Set-ItemProperty -Path $reg_accent -Name "AccentColor" -Value 0xff000000 -Type Dword -Force
    Set-ItemProperty -Path $reg_accent -Name "AccentColorMenu" -Value 0xff767676 -Type Dword -Force
    Set-ItemProperty -Path $reg_accent -Name "StartColorMenu" -Value 0xff4f4f4f -Type Dword -Force
    # hide desktop icons
    $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-ItemProperty -Path $path -Name "HideIcons" -Value 1
    $path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings"
    New-Item -Path "$path" -Force | Out-Null
    Set-ItemProperty -Path $path -Name "TaskbarEndTask" -Value 1 -Force
}

function win_declutter_home_folders() {
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

function win_declutter_osapps() {
    log_msg "win_declutter_osapps"
    winget_uninstall "Mail and Calendar"
    winget_uninstall "MSN Weather"
    winget_uninstall "Microsoft Sticky Notes"
    winget_uninstall "Microsoft Clipchamp"
    winget_uninstall "Solitaire & Casual Games"
    winget_uninstall "Game Bar"
    winget_uninstall "News"
    winget_uninstall "Windows Maps"
    winget_uninstall "Microsoft People"
    winget_uninstall "Films & TV"
    winget_uninstall "Power Automate"
}

function win_declutter_3_and_4_fingers_gestures() {
    log_msg "win_declutter_3_and_4_fingers_gestures"
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

function win_declutter_unused_keyboard_shortcuts() {
    log_msg "win_declutter_unused_keyboard_shortcuts"
    
    # "disable win+v shortcut"
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    $valueName = "DisabledHotkeys"
    $keyToDisable = "V"
    $currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
    $newValue = $currentValue
    if ($null -eq $newValue -or $newValue -notlike "*$keyToDisable*") {
        $newValue = ($newValue | Out-String).Trim() + $keyToDisable
        Set-ItemProperty -Path $regPath -Name $valueName -Value $newValue
    }
    
    # "disable AutoRotation shortcuts"
    $igf = "HKCU:\Software\Intel\Display\Igfxcui"
    New-Item -Path $igf -Force | Out-Null
    Set-ItemProperty -Path $igf -Name "HotKeys" -Value 'Disable'

    # "disable language shortcuts"
    $reg_key_toggle = "HKCU:\Keyboard Layout\Toggle"
    Set-ItemProperty -Path $reg_key_toggle -Name "HotKey" -Value '3' -Type String
    Set-ItemProperty -Path $reg_key_toggle -Name "Language Hotkey" -Value '3' -Type String
    Set-ItemProperty -Path $reg_key_toggle -Name "Layout Hotkey" -Value '3' -Type String

    # "disable acessibility shortcuts"
    $reg_acess = "HKCU:\Control Panel\Accessibility"
    Set-ItemProperty -Path "$reg_acess\ToggleKeys" -Name "Flags" -Value '58' -Type String
    Set-ItemProperty -Path "$reg_acess\StickyKeys" -Name "Flags" -Value '26' -Type String
    New-Item -Path "$reg_acess\Keyboard Response" -Force | Out-Null
    Set-ItemProperty -Path "$reg_acess\Keyboard Response" -Name "Flags" -Value '122' -Type String
}

function win_declutter_bell_sounds() {
    log_msg "win_declutter_bell_sounds"
    Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\" "(Default)" -Value ".None"
    Get-ChildItem -Path 'HKCU:\AppEvents\Schemes\Apps' | Get-ChildItem | Get-ChildItem | Where-Object { $_.PSChildName -eq '.Current' } | Set-ItemProperty -Name '(Default)' -Value '' 
}

function win_declutter_web_search_and_widgets() {
    log_msg "win_declutter_web_search_and_widgets"
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

function win_declutter_explorer_listing_files() {
    log_msg "win_declutter_explorer_listing_files"
    $reg_explorer = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
    
    Set-ItemProperty -Path $reg_explorer -Name ShowFrequent -Value 0 -Type Dword
    Set-ItemProperty -Path $reg_explorer -Name ShowRecent -Value 0 -Type Dword
    Set-ItemProperty -Path $reg_explorer -Name ShowRecommendations -Value 0 -Type Dword
    Set-ItemProperty -Path $reg_explorer -Name HideFileExt -Value 0 -Type Dword
    Set-ItemProperty -Path $reg_explorer -Name DisableGraphRecentItems -Value 1 -Type Dword
    
    $reg_explorer_adv = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-ItemProperty -Path $reg_explorer_adv -Name ShowAccountBasedInsights -Value 0 -Type Dword
    Set-ItemProperty -Path $reg_explorer_adv -Name Start_TrackDocs -Value 0 -Type Dword
    Set-ItemProperty -Path $reg_explorer_adv -Name ShowRecommendedFiles -Value 0 -Type Dword
    Set-ItemProperty -Path $reg_explorer_adv -Name LaunchTo -Value 1 -Type Dword # This PC

    # disable grouping
    # https://answers.microsoft.com/en-us/windows/forum/all/completely-disable-file-grouping-always-everywhere/ac31a227-f585-4b0a-ab2e-a557828eaec5
    $key = 'HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell' 
    Remove-Item -Path "$key\BagMRU"  -Force -ErrorAction SilentlyContinue
}

function win_declutter_taskbar() {
    log_msg "win_declutter_taskbar"
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

function win_declutter_xbox() {
    log_msg "win_declutter_xbox"
    # https://www.makeuseof.com/windows-new-app-ms-gamingoverlay-error/

    $reg_game_dvr = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR"
    Set-ItemProperty -Path $reg_game_dvr -Name AppCaptureEnabled -Value 0 -Type Dword
    Set-ItemProperty -Path $reg_game_dvr -Name HistoricalCaptureEnabled -Value 0 -Type Dword
    $reg_game_store = "HKCU:\System\GameConfigStore"
    Set-ItemProperty -Path $reg_game_store -Name GameDVR_Enabled -Value 0 -Type Dword

    winget_uninstall 9MV0B5HZVK9Z
    winget_uninstall "Xbox TCUI" 
    winget_uninstall "Xbox Identity Provider" 
    winget_uninstall "Microsoft Edge Game Assist" 
    winget_uninstall Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe
}