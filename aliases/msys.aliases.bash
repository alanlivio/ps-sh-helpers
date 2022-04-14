alias unixpath='cygpath'
alias winpath='cygpath -w'
alias ls='ls --color=auto --hide=ntuser* --hide=NTUSER* --hide=AppData --hide=IntelGraphicsProfiles* --hide=MicrosoftEdgeBackups'
alias win_trash_clean='powershell -c "Clear-RecycleBin -Confirm:$false 2> $null"'
alias win_trash_open='powershell -c "Start-Process explorer shell:recyclebinfolder"'
alias explorer_restart='powershell -c "taskkill /f /im explorer | Out-Null; Start-Process explorer"'
alias explorer_hide_home_dotfiles="powershell -c 'Get-ChildItem \"\${env:userprofile}\.*\" | ForEach-Object { \$_.Attributes += \"Hidden\" }'"
alias explorer_tmp="powershell -c 'Start-Process explorer \"\${env:localappdata}\temp\"'"