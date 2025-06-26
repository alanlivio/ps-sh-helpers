function git_gitignore_create {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Contexts
    )
    (Invoke-WebRequest -Uri "https://www.toptal.com/developers/gitignore/api/$Contexts" -UseBasicParsing).Content
}

function git_gitignore_create_vscode {
    (Invoke-WebRequest -Uri "https://www.toptal.com/developers/gitignore/api/visualstudiocode" -UseBasicParsing).Content
}