function git_filter_repo_finish_push() {
    if [ -z "$BH_LAST_ORIGIN" ]; then
        log_msg "var BH_LAST_ORIGIN not defined (maybe this is a new shell after editing). please restart editing!"
        return
    fi

    log_msg "Is it to force push branch $BH_LAST_BRANCH to origin $BH_LAST_ORIGIN (y/n)? "
    answer=$(while ! head -c 1 | grep -i '[ny]'; do true; done)
    if echo "$answer" | grep -iq "^y"; then
        git remote add origin $BH_LAST_ORIGIN
        git push --set-upstream origin $BH_LAST_BRANCH --force
    fi
}

alias _git_filter_repo_save_origin_and_branch='if [[ -n $(git remote get-url origin) ]]; then BH_LAST_ORIGIN=$(git remote get-url origin); BH_LAST_BRANCH=$(git branch --show-current); fi'
alias _git_filter_repo_test_and_msg='if [ $? -eq 0 ]; then log_msg "fiter-repo succeeded. check if you agree and run git_filter_repo_finish_push to push"; fi'

function git_filter_repo_messages_to_lower_case() {
    _git_filter_repo_save_origin_and_branch
    log_msg git-filter-repo --message-callback "'return message.lower()'" --force
    _git_filter_repo_test_and_msg
}

function git_filter_repo_messages_remove_str() {
    : ${2?"Usage: ${FUNCNAME[0]} <str> "}
    _git_filter_repo_save_origin_and_branch
    log_msg git-filter-repo --message-callback "'return message.replace(b\"$1\", b\"\")'" --force
    _git_filter_repo_test_and_msg
}

function git_filter_repo_user_rename_to_current() {
    log_msg "Do want use the user.email=$(git config user.email)(y/n)? "
    answer=$(while ! head -c 1 | grep -i '[ny]'; do true; done)
    _git_filter_repo_save_origin_and_branch
    local new_name="$(git config user.name)"
    local new_email="$(git config user.email)"
    git-filter-repo --name-callback "'return b\"$new_name\"'" --email-callback "'return b\"$new_email\"'" --force
    _git_filter_repo_test_and_msg
}

function git_filter_repo_user_rename_as_mailmap() {
    _git_filter_repo_save_origin_and_branch
    : ${1?"Usage: ${FUNCNAME[0]} <mailmap>. See more at 'https://htmlpreview.github.io/?https://github.com/newren/git-filter-repo/blob/docs/html/git-filter-repo.html#:~:text=User%20and%20email%20based%20filtering'"}
    git-filter-repo --mailmap "$1" --force
    _git_filter_repo_test_and_msg
}

function git_filter_repo_delete_file_bigger_than_50M() {
    _git_filter_repo_save_origin_and_branch
    git-filter-repo --strip-blobs-bigger-than 50M --force
    _git_filter_repo_test_and_msg
}

function git_filter_repo_delete_file_bigger_than_1M() {
    _git_filter_repo_save_origin_and_branch
    git-filter-repo --strip-blobs-bigger-than 50M --force
    _git_filter_repo_test_and_msg
}

function git_filter_repo_delete_file() {
    : ${1?"Usage: ${FUNCNAME[0]} <filename>"}
    _git_filter_repo_save_origin_and_branch
    git-filter-repo --use-base-name --invert-paths --path "$1" --force
    _git_filter_repo_test_and_msg
}
