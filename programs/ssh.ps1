function ssh_send_authorized_public_key {
    param([Parameter(Mandatory = $true)][string]$UserServer)
    $publicKeyPath = Join-Path $env:userprofile ".ssh\id_rsa.pub"
    (Get-Content $publicKeyPath -Raw) -replace "`r`n", "`n"  | ssh "$UserServer" "sh -c 'cat - >> ~/.ssh/authorized_keys'"
}

function ssh_send_private_key {
    param([Parameter(Mandatory = $true)][string]$UserServer)
    $privateKeyPath = Join-Path $env:userprofile ".ssh\id_rsa"
    (Get-Content $privateKeyPath -Raw) -replace "`r`n", "`n" | ssh "$UserServer" "sh -c 'cat - > ~/.ssh/id_rsa;chmod 600 ~/.ssh/id_rsa'"
}