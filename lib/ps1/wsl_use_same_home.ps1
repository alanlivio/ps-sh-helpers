function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }

function wsl_get_default() {
    [System.Text.Encoding]::Unicode.GetString([System.Text.Encoding]::UTF8.GetBytes((wsl -l))) -split '\s\s+' | ForEach-Object {
        if ($_.Contains('(')) {
            return $_.Split(' ')[0]
        }
    }
}
function wsl_terminate() {
    wsl -t (wsl_get_default)
}

log_msg "setup wsl to use same home"
log_msg "target wsl is $(wsl_get_default)"
log_msg "terminate wsl"
wsl_terminate

if ((wsl echo '$HOME').Contains("Users")) {
    log_msg "WSL already use windows UserProfile as home."
    return
}

log_msg "fix file metadata"
# https://docs.microsoft.com/en-us/windows/wsl/wsl-config
# https://github.com/Microsoft/WSL/issues/3138
# https://devblogs.microsoft.com/commandline/chmod-chown-wsl-improvements/
wsl -u root bash -c 'echo "[automount]" > /etc/wsl.conf'
wsl -u root bash -c 'echo "enabled=true" >> /etc/wsl.conf'
wsl -u root bash -c 'echo "root=/mnt" >> /etc/wsl.conf'
wsl -u root bash -c 'echo "mountFsTab=false" >> /etc/wsl.conf'
wsl -u root bash -c 'echo "options=\"metadata,uid=1000,gid=1000,umask=0022,fmask=11\"" >> /etc/wsl.conf'

log_msg "enable sudoer"
wsl -u root usermod -aG sudo "$env:UserName"
wsl -u root usermod -aG root "$env:UserName"

log_msg "change default dir to /mnt/c/Users/"
wsl -u root skill -KILL -u $env:UserName
wsl -u root usermod -d /mnt/c/Users/$env:UserName $env:UserName

log_msg "create a link /home/user at /mnt/c/Users/user"
wsl -u root rm -rf /home/$env:UserName
wsl -u root ln -s /mnt/c/Users/$env:UserName /home/$env:UserName

log_msg "Changing file /home/user permissions "
wsl -u root chown $env:UserName:$env:UserName /mnt/c/Users/$env:UserName/*