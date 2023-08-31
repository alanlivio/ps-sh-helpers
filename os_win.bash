#########################
# essential aliases
#########################

alias powershell='powershell.exe'
alias explorer='explorer.exe'
alias winget='winget.exe'
alias wsl='wsl.exe'
alias ls='ls --color=auto -I NTUSER\* -I ntuser\* -I AppData -I Searches -I Favorites -I IntelGraphicsProfiles* -I MicrosoftEdgeBackups'

if [[ -n $WSL_DISTRO_NAME ]]; then
    alias winpath='wslpath -m'
else
    alias winpath='cygpath -m'
fi

#########################
# load scripts as aliases
#########################

for file in "$BH_DIR/scripts/"win_*.ps1; do
    if test -f $file &>/dev/null; then
        script_name=$(basename ${file%.*})
        eval "alias $script_name='powershell.exe $(winpath $file)'"
    fi
done

#########################
# basic
#########################

function win_home_hide_dotfiles() {
    # set Hidden to nodes .*
    powershell.exe -c 'Get-ChildItem "${env:userprofile}\\.*" | ForEach-Object { $_.Attributes += "Hidden" }'
}

function winget_install() {
    local pkgs_to_install=""
    for i in "$@"; do
        if [[ $(winget.exe list --id $i) =~ "No installed"* ]]; then
            pkgs_to_install="$i $pkgs_to_install"
        fi
    done
    if test ! -z "$pkgs_to_install"; then
        for pkg in $pkgs_to_install; do
            winget.exe install --accept-package-agreements --accept-source-agreements --silent $pkg
        done
    fi
}

function win_update() {
    log_msg "winget install pkgs from var BH_PKGS_WINGET: $BH_PKGS_WINGET"
    winget_install $BH_PKGS_WINGET
    log_msg "winget upgrade all"
    winget.exe upgrade --all --silent
    log_msg "win os upgrade"
    gsudo powershell.exe -c 'Install-Module -Name PSWindowsUpdate -Force; Install-WindowsUpdate -AcceptAll -IgnoreReboot'
}

function win_ssh_add_identity() {
    gsudo powershell.exe -c 'Set-Service ssh-agent -StartupType Automatic'
    gsudo powershell.exe -c 'Start-Service ssh-agent'
    gsudo powershell.exe -c 'Get-Service ssh-agent'
    gsudo powershell.exe -c 'ssh-add "$env:userprofile\\.ssh\\id_rsa"'
}

#########################
# start
#########################

function start_from_wsl() {
    if ! type wslview &>/dev/null; then sudo apt install wslu; fi
    wslview "$@"
}

#########################
# regedit
#########################

function regedit_open_path() {
    powershell.exe -c "
    reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\ /v Lastkey /d 'Computer\\$1' /t REG_SZ /f
    regedit.exe
  "
}

function regedit_open_shell_folders() {
    regedit_open_path 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
}

#########################
# env & path
#########################

function win_env_show() {
    powershell.exe -c '[System.Environment]::GetEnvironmentVariables()'
}

function win_env_add() {
    : ${2?"Usage: ${FUNCNAME[0]} <varname> <value>"}
    powershell.exe -c "[System.Environment]::SetEnvironmentVariable('$1', '$2', 'user')"
}

function win_path_show() {
    powershell.exe -c '(Get-ChildItem Env:Path).Value'
}

function win_path_show_as_list() {
    IFS=';' read -ra ADDR <<<"$(win_path_show)"
    for i in "${!ADDR[@]}"; do echo ${ADDR[$i]}; done
}

#########################
# msys2
#########################
alias msys2_start='cmd.exe /mnt/c/msys64/msys2_shell.cmd -defterm -mingw64 -no-start'
if type pacman &>/dev/null; then
    alias msys2_search='pacman -s --noconfirm'
    alias msys2_show='pacman -Qi'
    alias msys2_list_installed='pacman -Qqe'
    alias msys2_install='pacman -S --noconfirm'
    alias msys2_uninstall='pacman -R --noconfirm'
    alias msys2_use_same_home='echo db_home: windows >>/etc/nsswitch.conf'
fi

#########################
# sanity/disable/enable
#########################

function win_policy_reset() {
    gsudo cmd.exe /C 'RD /S /Q %WinDir%\System32\GroupPolicyUsers '
    gsudo cmd.exe /C 'RD /S /Q %WinDir%\System32\GroupPolicy '
    gsudo gpupdate.exe /force
}