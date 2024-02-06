alias git_count_commits='git rev-list --all --count'
alias git_count_commits_by_user='git shortlog -s -n'
alias git_diff_files_last_commit='git diff --stat HEAD^1'
alias git_diff_last_commit='git diff HEAD^1'

function git_fix_ssh() {
    # https://stackoverflow.com/questions/9270734/ssh-permissions-are-too-open
    chmod 700 $HOME/.ssh/
    chmod 600 $HOME/.ssh/id_rsa
    chmod 600 $HOME/.ssh/id_rsa.pubssh-rsa
    ssh -T git@github.com
}

function git_assume_unchanged() {
    : ${1?"Usage: ${FUNCNAME[0]} <file>"}
    git update-index --assume-unchanged $1
}

function git_assume_unchanged_disable() {
    : ${1?"Usage: ${FUNCNAME[0]} <file>"}
    git update-index --no-assume-unchanged $1
}

function git_branch_remove_local_and_remote() {
    : ${1?"Usage: ${FUNCNAME[0]} <branch-name>"}
    git branch -d $1
    git push origin --delete $1
}

function git_branch_all_remotes_checkout_and_reset() {
    local CURRENT=$(git branch --show-current)
    git fetch -p origin
    git branch -r | grep -v '\->' | while read -r remote; do
        git reset --hard
        git clean -ndf
        _log_msg "updating ${remote#origin/}"
        git checkout "${remote#origin/}"
        if test $? != 0; then
            _log_error "cannot goes to ${remote#origin/} because there are local changes" && return 1
        fi
        git pull --all
        if test $? != 0; then
            _log_error "cannot pull ${remote#origin/} because there are local changes" && return 1
        fi
    done
    _log_msg "returning to branch $CURRENT"
    git checkout $CURRENT
}

function git_push_after_amend_all() {
    git commit -a --amend --no-edit
    git push --force
}

function git_gitignore_create() {
    : ${1?"Usage: ${FUNCNAME[0]} <contexts,..>"}
    curl -L -s "https://www.gitignore.io/api/$1"
}

function git_formated_patch_n_last_commits() {
    : ${1?"Usage: ${FUNCNAME[0]} <number_of_last_commits>"}
    git format-patch HEAD~$1
}

function git_formated_patch_apply() {
    git am <"$@"
}

function git_subdirs_pull() {
    find . -type d -iname .git | sed 's/\.git//g' | while read i; do
        (
            cd "$i"
            if test -d .git; then
                _log_msg "pull on $i"
                git pull
            fi
        )
    done
}

function git_subdirs_reset_clean() {
    find . -type d -iname .git | sed 's/\.git//g' | while read i; do
        (
            cd "$i"
            if test -d .git; then
                _log_msg "pull on $i"
                git reset --hard
                git clean -df
                git pull
            fi
        )
    done
}

function git_tag_move_to_head_and_push() {
    git tag -d $1
    git tag $1
    git push --force --tags
}

# git filter repo

function git_filter_repo_finish_push() {
    if [ -z "$BH_FILTER_REPO_LAST_ORIGIN" ]; then
        _log_msg "var BH_FILTER_REPO_LAST_ORIGIN not defined (maybe this is a new shell after editing). please restart editing!"
        return
    fi
    _log_msg -n "Is it to push into origin $BH_FILTER_REPO_LAST_ORIGIN and branch master (y/n)? "
    answer=$(while ! head -c 1 | grep -i '[ny]'; do true; done)
    if _log_msg "$answer" | grep -iq "^y"; then
        git remote add origin $BH_FILTER_REPO_LAST_ORIGIN
        git push --set-upstream origin master --force
    fi
}

alias _git_filter_repo_save_origin='if [[ -n $(git remote get-url origin) ]]; then BH_FILTER_REPO_LAST_ORIGIN=$(git remote get-url origin); fi'
alias _git_filter_repo_test_and_msg='if [ $? -eq 0 ]; then _log_msg "fiter-repo succeeded. check if you agree and run git_filter_repo_finish_push to push"; fi'

function git_filter_repo_messages_to_lower_case() {
    _git_filter_repo_save_origin
    _log_msg git filter-repo --message-callback "'return message.lower()'" --force | bash
    _git_filter_repo_test_and_msg
}

function git_filter_repo_messages_remove_str() {
    : ${2?"Usage: ${FUNCNAME[0]} <str> "}
    _git_filter_repo_save_origin
    _log_msg git filter-repo --message-callback "'return message.replace(b\"$1\", b\"\")'" --force | bash
    _git_filter_repo_test_and_msg
}

function git_filter_repo_user_rename_to_current() {
    _log_msg -n "Do want use the user.email=$(git config user.email)(y/n)? "
    answer=$(while ! head -c 1 | grep -i '[ny]'; do true; done)
    _git_filter_repo_save_origin
    local new_name="$(git config user.name)"
    local new_email="$(git config user.email)"
    _log_msg git filter-repo --name-callback "'return b\"$new_name\"'" --email-callback "'return b\"$new_email\"'" --force | bash
    _git_filter_repo_test_and_msg
}

function git_filter_repo_user_rename_as_mailmap() {
    _git_filter_repo_save_origin
    : ${1?"Usage: ${FUNCNAME[0]} <mailmap>. See more at 'https://htmlpreview.github.io/?https://github.com/newren/git-filter-repo/blob/docs/html/git-filter-repo.html#:~:text=User%20and%20email%20based%20filtering'"}
    git filter-repo --mailmap "$1" --force
    _git_filter_repo_test_and_msg
}

function git_filter_repo_delete_file_bigger_than_50M() {
    _git_filter_repo_save_origin
    git filter-repo --strip-blobs-bigger-than 50M --force
    _git_filter_repo_test_and_msg
}

function git_filter_repo_delete_file() {
    : ${1?"Usage: ${FUNCNAME[0]} <filename>"}
    _git_filter_repo_save_origin
    git filter-repo --use-base-name --invert-paths --path "$1" --force
    _git_filter_repo_test_and_msg
}
