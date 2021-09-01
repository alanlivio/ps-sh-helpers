function bh_enable_ssh_server_pwsh {
  # add capabilities
  # https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/ssh-remoting-in-powershell-core?view=powershell-7.1
  # https://www.thomasmaurer.ch/2020/04/enable-powershell-ssh-remoting-in-powershell-7/
  Add-WindowsCapability -Online -Name OpenSSH.Client
  Add-WindowsCapability -Online -Name OpenSSH.Server
  Start-Service sshd
  Set-Service -Name sshd -StartupType 'Automatic'

  # set powershell as default shell
  # https://github.com/PowerShell/Win32-OpenSSH/wiki/DefaultShell
  New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
}

bh_enable_ssh_server_pwsh