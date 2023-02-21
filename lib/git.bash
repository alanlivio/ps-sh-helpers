alias git_overleaf_push_commit_all='git commit -am "Update from local git";git push'
alias git_count_commits='git rev-list --all --count'
alias git_count_commits_by_user='git shortlog -s -n'
alias git_untrack_repo_file_options_changes='git config core.fileMode false'
alias git_stash_list='git stash save --include-untracked'
alias git_branch_show_remotes='git remote show origin'
alias git_diff_files_last_commit='git diff --stat HEAD^1'
alias git_diff_last_commit='git diff HEAD^1'

function git_github_fix() {
  echo -e "Host github.com\\n  Hostname ssh.github.com\\n  Port 443" | tee $HOME/.ssh/config
  ssh -T git@github.com
  ssh-keyscan -t rsa github.com >>~/.ssh/known_hosts
}

function git_assume_unchanged() {
  : ${1?"Usage: ${FUNCNAME[0]} <file>"}
  git update-index --assume-unchanged $1
}

function git_assume_unchanged_disable() {
  : ${1?"Usage: ${FUNCNAME[0]} <file>"}
  git update-index --no-assume-unchanged $1
}

function git_show_file_in_commit() {
  : ${1?"Usage: ${FUNCNAME[0]} <commit> <file>"}
  REV=$1
  FILE=$2
  git show $REV:$FILE
}

function git_branch_push() {
  : ${1?"Usage: ${FUNCNAME[0]} <branch-name>"}
  git push -u origin $1
}

function git_branch_delete_local_and_origin() {
  : ${1?"Usage: ${FUNCNAME[0]} <branch-name>"}
  git branch -d $1
  git push origin --delete $1
}

function git_branch_all_remotes_checkout_and_reset_hard() {
  local CURRENT=$(git branch --show-current)
  git fetch -p origin
  git branch -r | grep -v '\->' | while read -r remote; do
    git reset --hard
    git clean -ndf
    log_msg "updating ${remote#origin/}"
    git checkout "${remote#origin/}"
    if test $? != 0; then
      log_error "cannot goes to ${remote#origin/} because there are local changes" && return 1
    fi
    git pull --all
    if test $? != 0; then
      log_error "cannot pull ${remote#origin/} because there are local changes" && return 1
    fi
  done
  log_msg "returning to branch $CURRENT"
  git checkout $CURRENT
}

function git_branch_all_remotes_remove_local() {
  git branch | grep -v develop | xargs -r git branch -d
}

function git_branch_upstrem_set() {
  : ${1?"Usage: ${FUNCNAME[0]} <remote-branch>"}
  git branch --set-upstream-to $1
}

function git_push_amend_all() {
  git commit -a --amend --no-edit
  git push --force
}

function git_push_commit_all() {
  : ${1?"Usage: ${FUNCNAME[0]} <commit_message>"}
  echo $1
  git commit -am "$1"
  git push
}

function git_gitignore_create() {
  : ${1?"Usage: ${FUNCNAME[0]} <contexts,..>"}
  curl -L -s "https://www.gitignore.io/api/$1"
}

function git_gitignore_create_python() {
  git_gitignore_create python
}

function git_formated_patch_n_last_commits() {
  : ${1?"Usage: ${FUNCNAME[0]} <number_of_last_commits>"}
  git format-patch HEAD~$1
}

function git_formated_patch_apply() {
  git am <"$@"
}


function git_subdirs_pull() {
  local cwd=$(pwd)
  local dir=$(pwd $0)
  cd $dir
  for i in $(find . -type d -iname .git | sed 's/\.git//g'); do
    cd "$dir/$i"
    if test -d .git; then
      log_msg "pull on $i"
      git pull
    fi
    cd ..
  done
  cd $cwd
}

function git_subdirs_reset_clean() {
  local cwd=$(pwd)
  local dir=$(pwd $1)
  cd $dir
  for i in $(find . -type d -iname .git | sed 's/\.git//g'); do
    cd "$dir/$i"
    if test -d .git; then
      log_msg "reset and clean on $i"
      git reset --hard
      git clean -df
    fi
    cd ..
  done
  cd $cwd
}

function git_tag_list() {
  git tag -l
}

function git_tag_move_to_head_and_push() {
  git tag -d $1
  git tag $1
  git push --force --tags
}

alias _git_filter_repo_test_and_msg='if [ $? -eq 0 ]; then log_msg "fiter-repo succeeded. check if you agree and run git_filter_repo_finish to push"; fi'
alias _git_filter_repo_save_origin='if [[ -n $(git remote get-url origin) ]]; then BH_FILTER_REPO_LAST_ORIGIN=$(git remote get-url origin); fi'

function git_filter_repo_messages_to_lower_case() {
  _git_filter_repo_save_origin
  echo git filter-repo --message-callback "'return message.lower()'" --force | bash
  _git_filter_repo_test_and_msg
}

function git_filter_repo_messages_remove_str() {
  : ${2?"Usage: ${FUNCNAME[0]} <str> "}
  _git_filter_repo_save_origin
  echo git filter-repo --message-callback "'return message.replace(b\"$1\", b\"\")'" --force | bash
  _git_filter_repo_test_and_msg
}

function git_filter_repo_user_rename_to_current() {
  _git_filter_repo_save_origin
  local new_name="$(git config user.name)"
  local new_email="$(git config user.email)"
  echo git filter-repo --name-callback "'return b\""$new_name"\"'" --email-callback "'return b\""$new_email"\"'" --force | bash
  _git_filter_repo_test_and_msg
}

function git_filter_repo_user_rename_as_mailmap() {
  _git_filter_repo_save_origin
  : ${1?"Usage: ${FUNCNAME[0]} <mailmap>. See more at 'https://htmlpreview.github.io/?https://github.com/newren/git-filter-repo/blob/docs/html/git-filter-repo.html#:~:text=User%20and%20email%20based%20filtering'"}
  git filter-repo --mailmap $1
  _git_filter_repo_test_and_msg
}

function git_filter_repo_delete_file_bigger_than_50M() {
  _git_filter_repo_save_origin
  git filter-repo --strip-blobs-bigger-than 50M
  _git_filter_repo_test_and_msg
}

function git_filter_repo_delete_file() {
  : ${1?"Usage: ${FUNCNAME[0]} <filename>"}
  _git_filter_repo_save_origin
  git filter-repo --use-base-name --invert-paths --path "$1"
  _git_filter_repo_test_and_msg
}

function git_filter_repo_finish_push() {
  if [ -z "$BH_FILTER_REPO_LAST_ORIGIN" ]; then
    echo "$BH_FILTER_REPO_LAST_ORIGIN not defined fix it"
    return
  fi
  echo -n "Is it to push into origin $BH_FILTER_REPO_LAST_ORIGIN and branch master (y/n)? "
  answer=$(while ! head -c 1 | grep -i '[ny]'; do true; done)
  if echo "$answer" | grep -iq "^y"; then
    if [[ $(git remote get-url origin 2>/dev/null) != "$BH_FILTER_REPO_LAST_ORIGIN" ]]; then
      git remote add origin $BH_FILTER_REPO_LAST_ORIGIN
    fi
    git push --set-upstream origin master --force
  fi
}
