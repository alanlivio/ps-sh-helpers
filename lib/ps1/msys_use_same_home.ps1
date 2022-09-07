function log() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }
$MSYS_HOME = "C:\msys64"
if (!(Test-Path $MSYS_HOME)) {
    log "msys not exist at $MSYS_HOME"
    return
}
Set-Alias msysbash "$MSYS_HOME\usr\bin\bash.exe"
msysbash -c 'echo none / cygdrive binary,posix=0,noacl,user 0 0 > /etc/fstab'
msysbash -c 'echo C:/Users/ /Users ntfs binary,noacl,auto 1 1 >>  /etc/fstab'
msysbash -c ' echo db_home: windows >> /etc/nsswitch.conf'
msysbash -c ' echo /c /mnt/c none bind >> /etc/fstab' # mount /mnt/c/ like in WSL