function git_clone_or_pull {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Usage: git_clone_or_pull <url> <basedir> [<name>] [<email>]. It fetchs repo to <basedir>/<name>. If <name> is empty, the <url> basename is used.")]
        [string]$url,
        [Parameter(Mandatory = $true)]
        [string]$basedir,
        [string]$name,
        [string]$email
    )
    log_msg "git_clone_or_pull $url"
    if (-not (Test-Path $basedir)) {
        New-Item -Path $basedir -ItemType Directory -Force
    }
    if ([string]::IsNullOrEmpty($name)) {
        $dir = Join-Path $basedir (Split-Path $url -Leaf)
    } else {
        $dir = Join-Path $basedir $name
    }
    if (Test-Path $dir) {
        Push-Location $dir
        git pull
        Pop-Location
    } else {    
        git clone $url $dir
        if (-not ([string]::IsNullOrEmpty($email))) {
            Push-Location $dir
            git config user.email "$email"
            Pop-Location
        }
    }
}

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


function git_branch_remove_local_and_remote {
    param ( [Parameter(Mandatory = $true)] [string]$branchname )
    git branch -d $branchname
    git push origin --delete $branchname
}

function git_push_after_amend_all {
    git commit -a --amend --no-edit
    git push --force
}

function git_formated_patch_n_last_commits {
    param ( [Parameter(Mandatory = $true)] [int]$number_of_last_commits )
    git format-patch HEAD~$number_of_last_commits
}

function git_formated_patch_apply {
    param ( [Parameter(Mandatory = $true)] [string[]]$args )
    foreach ($file in $args) {
        git am $file
    }
}

function git_tag_move_to_head_and_push {
    param ( [Parameter(Mandatory = $true)] [string]$tagname )
    git tag -d $tagname
    git tag $tagname
    git push --force --tags
}
