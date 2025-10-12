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

function win_admin_current_user_disable() {
    $current_user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    net localgroup 'Administrators' $current_user /delete
}

function win_admin_current_user_enable {
    $current_user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    net localgroup 'Administrators' $current_user /add
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
    if (!(Test-Path $exePath)) {
        # download
        if ($url_or_path_to_zip.StartsWith("http://") -or $url_or_path_to_zip.StartsWith("https://")) {
            $url = New-Object System.Uri($url_or_path_to_zip)
            $derivedZipFileName = [System.IO.Path]::GetFileName($url.LocalPath)
            $outZip = Join-Path $env:TEMP $derivedZipFileName
            if (Test-Path $outZip) {
                log_msg "skip download and using existing $outZip"
            } else {
                $webClient = New-Object System.Net.WebClient
                $webClient.DownloadFile($url, $outZip)
                if (!(Test-Path $outZip)) { log_error "download failed"; return }
            }
            $sourceZipFilePath = $outZip
        } else {
            $sourceZipFilePath = $url_or_path_to_zip
        }
        # extract, using a randomExtractFolder may needed when no internal folder.
        $randomExtractFolder = [System.Guid]::NewGuid().ToString().Replace("-", "")
        $tempExtractPath = Join-Path $env:TEMP $randomExtractFolder
        New-Item -ItemType Directory -Path $tempExtractPath | Out-Null
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        try { 
            [System.IO.Compression.ZipFile]::ExtractToDirectory($sourceZipFilePath, $tempExtractPath) 
        } catch { log_error "extract failed"; return }
        if (!(Test-Path $extractPath)) { New-Item -ItemType Directory -Path $extractPath | Out-Null }
        # if the basename of extractPath exist inside extracted Path so get from inside that folder
        $extractPathBasename = (Split-Path -Path $extractPath -Leaf)
        if (Test-Path (Join-Path $tempExtractPath $extractPathBasename)) {
            Copy-Item -Path "$tempExtractPath\$extractPathBasename\*" -Destination $extractPath -Recurse -Force
        } else {
            Copy-Item -Path "$tempExtractPath\*" -Destination $extractPath -Recurse -Force
        }
    }
}

function win_install_vlc() {
    $vlcExists = Get-ChildItem -Path "$env:LOCALAPPDATA\Programs" -Directory -Filter "vlc-*" | Where-Object { $_.Name -match "^vlc-\d+\.\d+\.\d+$" }
    if ($vlcExists) { return; }
    $vlcLatestWin64Url = "https://get.videolan.org/vlc/last/win64/"
    $webRequest = Invoke-WebRequest -Uri $vlcLatestWin64Url -Method Get -ErrorAction Stop
    $vlcZipLink = $webRequest.Links | Where-Object { $_.href -like "*win64.zip" } | Select-Object -First 1
    if (-not ($vlcZipLink)) { log_error "Download failed"; return }
    $vlcZip = $vlcZipLink.href
    $url = "https://get.videolan.org/vlc/last/win64/$vlcZip"
    $name = $vlcZip -replace '-win64\.zip$'
    win_install_exe_from_zip $url "$env:LOCALAPPDATA\Programs\$name" "vlc.exe"
    win_startmenu_add_lnk_to_allapps "$env:LOCALAPPDATA\Programs\$name\vlc.exe"
}

function win_install_obs() {
    if (Test-Path "$env:LOCALAPPDATA\Programs\OBS\bin\64bit\obs64.exe") { return; }
    $apiUrl = "https://api.github.com/repos/obsproject/obs-studio/releases/latest"
    $response = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers @{"Accept" = "application/vnd.github.v3+json" }
    if (-not ($response)) { log_error "Download failed"; return }
    $version = $response.tag_name
    $url = "https://github.com/obsproject/obs-studio/releases/download/$version/OBS-Studio-$version-Windows-x64.zip"
    win_install_exe_from_zip $url "$env:LOCALAPPDATA\Programs\OBS" "bin\64bit\obs64.exe"
    win_startmenu_add_lnk_to_allapps "$env:LOCALAPPDATA\Programs\OBS\bin\64bit\obs64.exe" OBS
}

function win_install_gh() {
    if (Test-Path "$env:LOCALAPPDATA\Programs\gh\bin\gh.exe") { return; }
    $apiUrl = "https://api.github.com/repos/cli/cli/releases/latest"
    $response = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers @{"Accept" = "application/vnd.github.v3+json" }
    if (-not ($response)) { log_error "Download failed"; return }
    $version = $response.tag_name.Substring(1)
    $url = "https://github.com/cli/cli/releases/download/v$version/gh_${version}_windows_amd64.zip" 
    win_install_exe_from_zip $url "$env:LOCALAPPDATA\Programs\gh" "bin\gh.exe"
    win_path_add "$env:LOCALAPPDATA\Programs\gh\bin"
}

function win_install_node() {
    if (Test-Path "$env:LOCALAPPDATA\Programs\nodejs") { return; }
    $nodeIndexUrl = "https://nodejs.org/dist/index.json"
    $nodeIndex = Invoke-RestMethod -Uri $nodeIndexUrl
    $latestLTS = $nodeIndex | Where-Object { $_.lts } | Select-Object -First 1
    $version = $latestLTS.version.TrimStart("v")  # e.g. "20.12.2"
    $arch = "x64"
    $url = "https://nodejs.org/dist/v$version/node-v$version-win-$arch.zip"
    win_install_exe_from_zip $url "$env:LOCALAPPDATA\Programs\nodejs" "node-v$version-win-$arch\node.exe"
    win_path_add "$env:LOCALAPPDATA\Programs\nodejs\node-v$version-win-$arch\"
}

function win_install_latex() {
    winget_install MikTex.MikTex
    # install perl required by latexmk 
    if (Test-Path "$env:LOCALAPPDATA\Programs\StrawberryPerl") { return; } 
    $apiUrl = "https://api.github.com/repos/StrawberryPerl/Perl-Dist-Strawberry/releases/latest"
    $response = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers @{"Accept" = "application/vnd.github.v3+json" }
    if (-not ($response)) { log_error "Download failed"; return }
    $asset = $response.assets | Where-Object {
        $_.name -match '^strawberry-perl-[\d\.]+-64bit-portable\.zip$'
    } | Select-Object -First 1
    $url = $asset.browser_download_url
    log_msg "download and extracting StrawberryPerl (~15min)"
    win_install_exe_from_zip $url "$env:LOCALAPPDATA\Programs\StrawberryPerl" "perl\bin\perl.exe"
    log_msg "download and extracting finished"
    win_path_add("${env:localappdata}\Programs\StrawberryPerl\perl\bin")
}

function win_install_ffmpeg() {
    winget_install Gyan.FFmpeg
    win_path_add("${env:localappdata}\Microsoft\WinGet\Packages\Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe\ffmpeg-7.1.1-full_build\bin")
}

function win_install_vim() {
    if (Test-Path "$env:LOCALAPPDATA\Programs\vim\vim91\vim.exe") { return; }  
    winget install vim.vim --location="$env:LOCALAPPDATA\Programs\vim"
    win_path_add "$env:LOCALAPPDATA\Programs\vim\vim91"
}

function win_install_tor() {
    if (Test-Path "$env:LOCALAPPDATA\Programs\TorBrowser") { return; } # winget -q return false for TorBrowser
    winget install TorProject.TorBrowser --location="$env:LOCALAPPDATA\Programs\TorBrowser" 
    win_startmenu_add_lnk_to_allapps "$env:LOCALAPPDATA\Programs\TorBrowser\Browser\firefox.exe" TorBrowser
}

# -- winget --

function winget_upgrade() {
    log_msg "winget update"
    winget upgrade --all --accept-package-agreements --accept-source-agreements --scope user
}

function winget_install() {
    winget list --accept-source-agreements -q $args[0] | Out-Null # first arg is the id
    if (-not($?)) {
        winget install "$args" --accept-package-agreements --accept-source-agreements
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
    if (-not(Test-Path $addPath)) { log_error "'$addPath' is not a valid path."; return }
    $path = [Environment]::GetEnvironmentVariable('path', 'User')
    $regexAddPath = [regex]::Escape($addPath)
    $arrPath = $path -split ';' | Where-Object { $_ -notMatch "^$regexAddPath\\?" }
    $newpath = ($arrPath + $addPath) -join ';'
    [Environment]::SetEnvironmentVariable("path", $newpath, 'User')
}

function win_path_list() {
    (Get-ChildItem Env:Path).Value -split ';'
}

# -- explorer --

function explorer_restart() {
    log_msg "explorer_restart"
    Stop-Process -Force -ErrorAction SilentlyContinue -ProcessName Explorer
}

function explorer_reset_shell_folders {
    $folders_expandable = @{
        "My Music"    = "%USERPROFILE%\Music"
        "Personal"    = "%USERPROFILE%\Documents"
        "My Video"    = "%USERPROFILE%\Videos"
        "My Pictures" = "%USERPROFILE%\Pictures"
    }
    $reg_path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    New-Item -Path $reg_path -Force | Out-Null
    foreach ($name in $folders_expandable.Keys) {
        $expand_value = $folders_expandable[$name]
        $real_path = [Environment]::ExpandEnvironmentVariables($expand_value)
        New-ItemProperty -Path $reg_path -Name $name -Value $expand_value -PropertyType ExpandString -Force | Out-Null
        if (-not (Test-Path -LiteralPath $real_path)) {
            New-Item -ItemType Directory -Path $real_path -Force | Out-Null
        }
    }
    explorer_restart
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

function explorer_hide_home_dotfiles {
    $paths = Get-ChildItem -LiteralPath $env:userprofile -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like '.*' -or $_.Name -like '*.lock' } |
    Select-Object -ExpandProperty FullName
    $paths = $paths | Where-Object { Test-Path -LiteralPath $_ }
    $hidden = [IO.FileAttributes]::Hidden
    foreach ($p in $paths) {
        $i = Get-Item -LiteralPath $p -Force
        if (-not $i.Attributes.HasFlag($hidden)) { $i.Attributes = $i.Attributes -bor $hidden }
    }
}

function explorer_hide_unused_and_shell_folders {
    $roots = @($env:OneDrive, $env:OneDriveCommercial) | Where-Object { $_ } | Sort-Object -Unique
    $subs = @('Apps', 'Whiteboards', 'Attachments', 'Scans', 'Microsoft Copilot Chat Files', 'Microsoft Teams Chat Files', 'Documents', 'Desktop')
    $folders = foreach ($r in $roots) { foreach ($s in $subs) { Join-Path $r $s } }
    $folders_extra = 'CrossDevice', 'vimfiles', 'vscode-remote-wsl', 'Contacts', 'Documents', 'Music', 'Games', 'Videos', 'Links', 'Favorites', 'Saved Games', 'Searches' |
    ForEach-Object { Join-Path $env:userprofile $_ }
    $paths = $folders + $folders_extra
    $paths = $paths | Sort-Object -Unique | Where-Object { Test-Path -LiteralPath $_ }
    $hidden = [IO.FileAttributes]::Hidden
    foreach ($p in $paths) {
        $i = Get-Item -LiteralPath $p -Force
        if (-not $i.Attributes.HasFlag($hidden)) { $i.Attributes = $i.Attributes -bor $hidden }
    }
}


# -- wsl --

function bash_ic() {
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$cmd
    )
    bash -i -c "$cmd"
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

function win_office_disable_warn_local_link {
    # requireq admin
    $regPaths = @(
        "HKCU:\Software\Microsoft\Office\16.0\Common\Security",
        "HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Security"
    )

    foreach ($path in $regPaths) {
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        New-ItemProperty -Path $path -Name "DisableHyperlinkWarning" -Value 1 -PropertyType DWord -Force | Out-Null
    }
}

function office_onenote_deeplink_from_url {
    param([Parameter(Mandatory)][string]$url)

    if (-not $script:onenote_cache) { $script:onenote_cache = @{} }
    if ($script:onenote_cache.ContainsKey($url)) { return $script:onenote_cache[$url] }

    Add-Type -AssemblyName System.Web | Out-Null
    $uri = [Uri]$url
    $qs = [System.Web.HttpUtility]::ParseQueryString($uri.Query)

    $resid = $qs['resid']
    $root_resid = ($resid -split '!')[0]
    $wd = $qs['wd']
    $decoded_wd = [System.Web.HttpUtility]::UrlDecode($wd)
    $decoded_wd -match 'target\((.+)\)' | Out-Null
    $target = $Matches[1]

    $parts = $target -split '\|'
    $notebook_file = $parts[0]
    $section_split = $parts[1] -split '/', 2
    $section_guid = $section_split[0]
    $section_name = $section_split[1]
    $page_guid = if ($parts.Count -ge 3 -and $parts[2]) { ($parts[2] -replace '/$', '') } else { $null }

    $section_name_escaped = [System.Uri]::EscapeDataString($section_name)
    $onenote = "onenote:https://d.docs.live.net/$root_resid/$notebook_file#$section_name_escaped&section-id={$section_guid}"
    if ($page_guid) { $onenote += "&page-id={$page_guid}" }
    $onenote += "&end"

    $script:onenote_cache[$url] = $onenote
    $onenote
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
    ssh-add "${env:userprofile}\\.ssh\\id_rsa"
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

# -- win_clutter --

function win_declutter_all() {
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
    explorer_restart
}

function win_declutter_all_dev() {
    winget_uninstall 9P6PMZTM93LR # Defender
    winget_uninstall 9WZDNCRD29V9 # Microsoft 365 Copilot
    winget_uninstall 9MSMLRH6LZF3 # Notepad
    winget_uninstall 9PCFS5B6T72H # Paint
    winget_uninstall "Phone Link"
    winget_uninstall "Windows Web Experience Pack"
    winget_uninstall "Windows Sound Recorder"
    winget_uninstall "Microsoft Store"
    winget_install Microsoft.VisualStudioCode
    winget_install Microsoft.WindowsTerminal
    win_declutter_all
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
        if (Test-Path "$_") {
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
    winget_uninstall "Microsoft Journal"
    winget_uninstall "Solitaire & Casual Games"
    winget_uninstall "Game Bar"
    winget_uninstall "News"
    winget_uninstall "Windows Maps"
    winget_uninstall "Microsoft People"
    winget_uninstall "Films & TV"
    winget_uninstall "Power Automate"
    winget_uninstall "Dev HOME"
    winget_uninstall 9PDJDJS743XF # Family
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
    Set-ItemProperty -Path $reg_explorer_adv -Name Start_TrackDocsInJumpLists -Value 0 -Type Dword
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