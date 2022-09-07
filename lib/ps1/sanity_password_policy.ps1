function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }

log_msg "sanity_password_policy"
$tmpfile = New-TemporaryFile
secedit /export /cfg $tmpfile /quiet
  (Get-Content $tmpfile).Replace("PasswordComplexity = 1", "PasswordComplexity = 0").Replace("MaximumPasswordAge = 42", "MaximumPasswordAge = -1") | Out-File $tmpfile
secedit /configure /db "$env:SYSTEMROOT\security\database\local.sdb" /cfg $tmpfile /areas SECURITYPOLICY | Out-Null
Remove-Item -Path $tmpfile