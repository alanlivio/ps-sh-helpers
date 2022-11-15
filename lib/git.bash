function git_github_fix() {
  echo -e "Host github.com\\n  Hostname ssh.github.com\\n  Port 443" | tee $HOME/.ssh/config
  ssh -T git@github.com
  ssh-keyscan -t rsa github.com >>~/.ssh/known_hosts
}

function git_count_commits() {
  git rev-list --all --count
}

function git_count_commits_by_user() {
  git shortlog -s -n
}

function git_overleaf_push_commit_all() {
  git commit -am "Update from local git"
  git push
}

function git_untrack_repo_file_options_changes() {
  git config core.fileMode false
}

function git_assume_unchanged() {
  : ${1?"Usage: ${FUNCNAME[0]} <file>"}
  git update-index --assume-unchanged $1
}

function git_assume_unchanged_disable() {
  : ${1?"Usage: ${FUNCNAME[0]} <file>"}
  git update-index --no-assume-unchanged $1
}

function git_reset_last_commit() {
  git reset HEAD~1
}

function git_reset_hard() {
  git reset --hard
}

function git_show_file_in_commit() {
  : ${1?"Usage: ${FUNCNAME[0]} <commit> <file>"}
  REV=$1
  FILE=$2
  git show $REV:$FILE
}

function git_stash_list() {
  git stash save --include-untracked
}

function git_branch_rebase_from_upstream() {
  git rebase upstream/master
}

function git_branch_push() {
  : ${1?"Usage: ${FUNCNAME[0]} <branch-name>"}
  git push -u origin $1
}

function git_branch_create_from_origin() {
  : ${1?"Usage: ${FUNCNAME[0]} <branch-name>"}
  git checkout -b $1
  git push -u origin $1
}

function git_branch_create_from_origin_all_reset_hard() {
  local CURRENT=$(git branch --show-current)
  git fetch -p origin
  git branch -r | grep -v '\->' | while read -r remote; do
    git reset --hard
    git clean -ndf
    log_msg "updating ${remote#origin/}"
    git checkout "${remote#origin/}"
    if test $? != 0; then
      log_error "cannot goes to ${remote#origin/} because there are local changes"
      exit
    fi
    git pull --all
    if test $? != 0; then
      log_error "cannot pull ${remote#origin/} because there are local changes"
      exit
    fi
  done
  log_msg "returning to branch $CURRENT"
  git checkout $CURRENT
}

function git_branch_show_remotes() {
  git remote show origin
}

function git_branch_delete_local_and_origin() {
  : ${1?"Usage: ${FUNCNAME[0]} <branch-name>"}
  git branch -d $1
  git push origin --delete $1
}

function git_branch_clean_removed_remotes() {
  git fetch --prune
  git branch -vv | awk '/: gone]/{print $1}' | xargs -r git branch -d
}

function git_branch_remove_all_local() {
  git branch | grep -v develop | xargs -r git branch -d
}

function git_branch_upstrem_set() {
  : ${1?"Usage: ${FUNCNAME[0]} <remote-branch>"}
  git branch --set-upstream-to $1
}

function git_partial_commit() {
  git stash
  git difftool -y stash
}

function git_partial_commit_continue() {
  git difftool -y stash
}

function git_github_setup() {
  : ${1?"Usage: ${FUNCNAME[0]} <github-name>"}
  NAME=$(basename "$1" ".${1##*.}")
  echo "setup github repo $NAME "

  echo "#" $NAME >README.md
  git setup
  git add README.md
  git commit -m "first commit"
  git remote add origin $1
  git push -u origin master
}

function git_upstream_pull() {
  git fetch upstream
  git rebase upstream/master
}

function git_push_force() {
  git push --force
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

function git_check_if_need_pull() {
  [ $(git rev-parse HEAD) = $(git ls-remote $(git rev-parse --abbrev-ref "@{u}" \
    | sed 's/\// /g') | cut -f1) ] && printf false || printf true
}

function git_gitignore_create() {
  : ${1?"Usage: ${FUNCNAME[0]} <contexts,..>"}
  curl -L -s "https://www.gitignore.io/api/$1"
}

function git_gitignore_create_python() {
  git_gitignore_create python
}

function git_gitignore_create_javascript() {
  git_gitignore_create node,bower,grunt
}

function git_gitignore_create_cpp() {
  git_gitignore_create c,c++,qt,autotools,make,ninja,cmake
}

function git_formated_patch_last_commit() {
  git format-patch HEAD~1
}

function git_formated_patch_n() {
  git format-patch HEAD~$1
}

function git_formated_patch_apply() {
  git am <"$@"
}

function git_diff_files_last_commit() {
  git diff --stat HEAD^1
}

function git_diff_last_commit() {
  git diff HEAD^1
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

function git_tag_v1_move_to_head_and_push() {
  git_tag_move_to_head_and_push 1.0
}

function git_tag_remove_local_and_remote() {
  : ${1?"Usage: ${FUNCNAME[0]} <tagname>"}
  git tag -d $1
  git push origin :refs/tags/$1
}

function git_amend_commit_all() {
  git commit -a --amend --no-edit
}

alias git_filter_repo_test_and_msg='if [ $? -eq 0 ]; then log_msg "fiter-repo succeeded. check if you agree and run git_filter_repo_finish to push"; fi'

function git_filter_repo_save_origin() {
  if [[ -n $(git remote get-url origin) ]]; then
    BH_FILTER_REPO_LAST_ORIGIN=$(git remote get-url origin)
  fi
}

function git_filter_repo_messages_to_lower_case() {
  git_filter_repo_save_origin
  echo git filter-repo --message-callback "'return message.lower()'" --force | bash
  git_filter_repo_test_and_msg
}

function git_filter_repo_messages_remove_str() {
  : ${2?"Usage: ${FUNCNAME[0]} <str> "}
  git_filter_repo_save_origin
  echo git filter-repo --message-callback "'return message.replace(b\"$1\", b\"\")'" --force | bash
  git_filter_repo_test_and_msg
}

function git_filter_repo_user_rename_to_current() {
  git_filter_repo_save_origin
  local new_name="$(git config user.name)"
  local new_email="$(git config user.email)"
  echo git filter-repo --name-callback "'return b\""$new_name"\"'" --email-callback "'return b\""$new_email"\"'" --force | bash
  git_filter_repo_test_and_msg
}

function git_filter_repo_user_rename_as_mailmap() {
  git_filter_repo_save_origin
  : ${1?"Usage: ${FUNCNAME[0]} <mailmap>. See more at 'https://htmlpreview.github.io/?https://github.com/newren/git-filter-repo/blob/docs/html/git-filter-repo.html#:~:text=User%20and%20email%20based%20filtering'"}
  git filter-repo --mailmap $1
  git_filter_repo_test_and_msg
}

function git_filter_repo_delete_file_bigger_than_50M() {
  git_filter_repo_save_origin
  git filter-repo --strip-blobs-bigger-than 50M
  git_filter_repo_test_and_msg
}

function git_filter_repo_delete_file() {
  : ${1?"Usage: ${FUNCNAME[0]} <filename>"}
  git_filter_repo_save_origin
  git filter-repo --use-base-name --invert-paths --path "$1"
  git_filter_repo_test_and_msg
}

function git_filter_repo_finish() {
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
