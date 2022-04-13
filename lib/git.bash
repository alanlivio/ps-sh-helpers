# ---------------------------------------
# git
# ---------------------------------------

# count

function bh_git_log_oneline() {
  git log --oneline
}

function bh_git_log_oneline_graph() {
  git log --oneline --graph --decorate --all
}

# count

function bh_git_count() {
  git rev-list --all --count
}

function bh_git_count_by_user() {
  git shortlog -s -n
}

# overleaf

function bh_git_overleaf_push_commit_all() {
  git commit -am "Update from local git"
  git push
}

# untrack

function bh_git_untrack_repo_file_options_changes() {
  git config core.fileMode false
}

# assume

function bh_git_assume_unchanged() {
  : ${1?"Usage: ${FUNCNAME[0]} <file>"}
  git update-index --assume-unchanged $1
}

function bh_git_assume_unchanged_disable() {
  : ${1?"Usage: ${FUNCNAME[0]} <file>"}
  git update-index --no-assume-unchanged $1
}

# reset

function bh_git_reset_last_commit() {
  git reset HEAD~1
}

function bh_git_reset_hard() {
  git reset --hard
}

# show

function bh_git_show_file_in_commit() {
  : ${1?"Usage: ${FUNCNAME[0]} <commit> <file>"}
  REV=$1
  FILE=$2
  git show $REV:$FILE
}

# stash

function bh_git_stash_list() {
  git stash save --include-untracked
}

# branch

function bh_git_branch_rebase_from_upstream() {
  git rebase upstream/master
}

function bh_git_branch_push() {
  : ${1?"Usage: ${FUNCNAME[0]} <branch-name>"}
  git push -u origin $1
}

function bh_git_branch_create_from_origin() {
  : ${1?"Usage: ${FUNCNAME[0]} <branch-name>"}
  git checkout -b $1
  git push -u origin $1
}

function bh_git_branch_create_from_origin_all_reset_hard() {
  local CURRENT=$(git branch --show-current)
  git fetch -p origin
  git branch -r | grep -v '\->' | while read -r remote; do
    git reset --hard
    git clean -ndf
    bh_log_msg "updating ${remote#origin/}"
    git checkout "${remote#origin/}"
    if test $? != 0; then
      bh_log_error "cannot goes to ${remote#origin/} because there are local changes"
      exit
    fi
    git pull --all
    if test $? != 0; then
      bh_log_error "cannot pull ${remote#origin/} because there are local changes"
      exit
    fi
  done
  bh_log_msg "returning to branch $CURRENT"
  git checkout $CURRENT
}

function bh_git_branch_show_remotes() {
  git remote show origin
}

function bh_git_branch_delete_local_and_origin() {
  : ${1?"Usage: ${FUNCNAME[0]} <branch-name>"}
  git branch -d $1
  git push origin --delete $1
}

function bh_git_branch_clean_removed_remotes() {
  # clean removed remotes
  git fetch --prune
  # clean banchs with removed upstreams
  git branch -vv | awk '/: gone]/{print $1}' | xargs -r git branch -d
}

function bh_git_branch_remove_all_local() {
  git branch | grep -v develop | xargs -r git branch -d
}

function bh_git_branch_upstrem_set() {
  : ${1?"Usage: ${FUNCNAME[0]} <remote-branch>"}
  git branch --set-upstream-to $1
}

# partial_commit

function bh_git_partial_commit() {
  git stash
  git difftool -y stash
}

function bh_git_partial_commit_continue() {
  git difftool -y stash
}

function bh_git_github_check_ssh() {
  ssh -T git@github.com
}

# github

function bh_git_github_fix() {
  echo -e "Host github.com\\n  Hostname ssh.github.com\\n  Port 443" | tee $HOME/.ssh/config
}

function bh_git_github_setup() {
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

# upstream

function bh_git_upstream_pull() {
  git fetch upstream
  git rebase upstream/master
}

# push

function bh_git_push_force() {
  git push --force
}

function bh_git_push_amend_all() {
  git commit -a --amend --no-edit
  git push --force
}

function bh_git_push_commit_all() {
  : ${1?"Usage: ${FUNCNAME[0]} <commit_message>"}
  echo $1
  git commit -am "$1"
  git push
}

# check

function bh_git_check_if_need_pull() {
  [ $(git rev-parse HEAD) = $(git ls-remote $(git rev-parse --abbrev-ref "@{u}" \
    | sed 's/\// /g') | cut -f1) ] && printf false || printf true
}

# gitignore

function bh_git_gitignore_create() {
  : ${1?"Usage: ${FUNCNAME[0]} <contexts,..>"}
  curl -L -s "https://www.gitignore.io/api/$1"
}

function bh_git_gitignore_create_python() {
  bh_git_gitignore_create python
}

function bh_git_gitignore_create_javascript() {
  bh_git_gitignore_create node,bower,grunt
}

function bh_git_gitignore_create_cpp() {
  bh_git_gitignore_create c,c++,qt,autotools,make,ninja,cmake
}

# formated_patch

function bh_git_formated_patch_last_commit() {
  git format-patch HEAD~1
}

function bh_git_formated_patch_n() {
  git format-patch HEAD~$1
}

function bh_git_formated_patch_apply() {
  git am <"$@"
}

# diff

function bh_git_diff_files_last_commit() {
  git diff --stat HEAD^1
}

function bh_git_diff_last_commit() {
  git diff HEAD^1
}

# subdirs

function bh_git_subdirs_pull() {
  local cwd=$(pwd)
  local dir=$(pwd $0)
  cd $dir
  for i in $(find . -type d -iname .git | sed 's/\.git//g'); do
    cd "$dir/$i"
    if test -d .git; then
      bh_log_msg "pull on $i"
      git pull
    fi
    cd ..
  done
  cd $cwd
}

function bh_git_subdirs_reset_clean() {
  local cwd=$(pwd)
  local dir=$(pwd $1)
  cd $dir
  for i in $(find . -type d -iname .git | sed 's/\.git//g'); do
    cd "$dir/$i"
    if test -d .git; then
      bh_log_msg "reset and clean on $i"
      git reset --hard
      git clean -df
    fi
    cd ..
  done
  cd $cwd
}

# tag

function bh_git_tag_list() {
  git tag -l
}

function bh_git_tag_move_to_head_and_push() {
  git tag -d $1
  git tag $1
  git push --force --tags
}

function bh_git_tag_v1_move_to_head_and_push() {
  bh_git_tag_move_to_head_and_push 1.0
}

function bh_git_tag_remove_local_and_remote() {
  : ${1?"Usage: ${FUNCNAME[0]} <tagname>"}
  git tag -d $1
  git push origin :refs/tags/$1
}

# amend

function bh_git_amend_commit_all() {
  git commit -a --amend --no-edit
}

# filter-repo tool 
# <https://htmlpreview.github.io/?https://github.com/newren/git-filter-repo/blob/docs/html/git-filter-repo.html>

alias bh_git_filter_repo_test_and_msg='if [ $? -eq 0 ]; then bh_log_msg "fiter-repo succeeded. check if you agree and run bh_git_filter_repo_finish to push"; fi'

function bh_git_filter_repo_save_origin() {
  if [[ -n $(git remote get-url origin) ]]; then
    BH_FILTER_REPO_LAST_ORIGIN=$(git remote get-url origin)
  fi
}

function bh_git_filter_repo_install() {
  bh_log_func
  bh_py_install git-filter-repo
}

function bh_git_filter_repo_messages_to_lower_case() {
  bh_log_func
  bh_git_filter_repo_save_origin
  # TODO: only work if echo |
  echo git filter-repo --message-callback "'return message.lower()'" --force | bash
  bh_git_filter_repo_test_and_msg
}

function bh_git_filter_repo_messages_remove_str() {
  : ${2?"Usage: ${FUNCNAME[0]} <str> "}
  bh_log_func
  bh_git_filter_repo_save_origin
  # TODO: only work if echo |
  echo git filter-repo --message-callback "'return message.replace(b\"$1\", b\"\")'" --force | bash
  bh_git_filter_repo_test_and_msg
}

function bh_git_filter_repo_user_rename_to_current() {
  bh_log_func
  bh_git_filter_repo_save_origin
  local new_name="$(git config user.name)"
  local new_email="$(git config user.email)"
  # TODO: only work if echo |
  echo git filter-repo --name-callback "'return b\""$new_name"\"'" --email-callback "'return b\""$new_email"\"'" --force | bash
  bh_git_filter_repo_test_and_msg
}

function bh_git_filter_repo_user_rename_as_mailmap() {
  bh_log_func
  bh_git_filter_repo_save_origin
  : ${1?"Usage: ${FUNCNAME[0]} <mailmap>. See more at 'https://htmlpreview.github.io/?https://github.com/newren/git-filter-repo/blob/docs/html/git-filter-repo.html#:~:text=User%20and%20email%20based%20filtering'"}
  git filter-repo --mailmap $1
  bh_git_filter_repo_test_and_msg
}

function bh_git_filter_repo_delete_file_bigger_than_50M() {
  bh_log_func
  bh_git_filter_repo_save_origin
  git filter-repo --strip-blobs-bigger-than 50M
  bh_git_filter_repo_test_and_msg
}

function bh_git_filter_repo_delete_file() {
  : ${1?"Usage: ${FUNCNAME[0]} <filename>"}
  bh_log_func
  bh_git_filter_repo_save_origin
  git filter-repo --use-base-name --invert-paths --path "$1"
  bh_git_filter_repo_test_and_msg
}

function bh_git_filter_repo_finish() {
  bh_log_func
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
