function git_gitignore_types_list {
    (Invoke-WebRequest -Uri "https://www.toptal.com/developers/gitignore/api/list" -UseBasicParsing).Content
}

function git_gitignore_types_add {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Usage: git_gitignore_type_add_current_folder <contexts,..>")]
        [string]$types
    )
    (Invoke-WebRequest -Uri "https://www.toptal.com/developers/gitignore/api/$types" -UseBasicParsing).Content
}

function git_gitignore_types_add_vscode {
    (Invoke-WebRequest -Uri "https://www.toptal.com/developers/gitignore/api/visualstudiocode" -UseBasicParsing).Content
}

function git_clone_to_dir {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Usage: git_clone_to_dir <url> <dir> [<name>] [<email>]. If <name> is empty, the <url> basename is used.")]
        [string]$url,
        [Parameter(Mandatory = $true)]
        [string]$dir,
        [string]$name,
        [string]$email
    )
    if ([string]::IsNullOrEmpty($name)) {
        $dir = Join-Path $dir (Split-Path $url -Leaf)
    } else {
        $dir = Join-Path $dir $name
    }
    if (-not (Test-Path $dir)) {
        git clone $url $dir
    }
    if (-not ([string]::IsNullOrEmpty($email))) {
        Push-Location $dir
        git config user.email "$email"
        Pop-Location
    }
}