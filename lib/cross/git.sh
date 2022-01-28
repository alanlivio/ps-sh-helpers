# ---------------------------------------
# git
# ---------------------------------------

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

function bh_git_branch_merge_without_merge_commit() {
  : ${1?"Usage: ${FUNCNAME[0]} <branch-name>"}
  git merge --ff-only $1
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

# edit

function bh_git_edit_tree_name_email() {
  git filter-branch -f --env-filter '
    NEW_NAME="$(git config user.name)"
    NEW_EMAIL="$(git config user.email)"
    export GIT_AUTHOR_NAME="$NEW_NAME"; 
    export GIT_AUTHOR_EMAIL="$NEW_EMAIL"; 
    export GIT_COMMITTER_NAME="$NEW_NAME"; 
    export GIT_COMMITTER_EMAIL="$NEW_EMAIL"; 
  ' --tag-name-filter cat -- --branches --tags
}

function bh_git_edit_tree__name_email_by_old_email() {
  : ${3?"Usage: ${FUNCNAME[0]} <old-name> <new-name> <new-email>"}
  git filter-branch --commit-filter '
    OLD_EMAIL="$1"
    NEW_NAME="$2"
    NEW_EMAIL="$3"
    if [ "$GIT_COMMITTER_EMAIL" = "$OLD_EMAIL" ]
    then
      export GIT_COMMITTER_NAME="$NEW_NAME"
      export GIT_COMMITTER_EMAIL="$NEW_EMAIL"
    fi
    if [ "$GIT_AUTHOR_EMAIL" = "$OLD_EMAIL" ]
    then
      export GIT_AUTHOR_NAME="$NEW_NAME"
      export GIT_AUTHOR_EMAIL="$NEW_EMAIL"
    fi
    ' --tag-name-filter cat -- --branches --tags
}

function bh_git_edit_tree_remove_file() {
  git filter-branch --force --index-filter 'git rm --cached --ignore-unmatch $1' --prune-empty --tag-name-filter cat -- --all
}

# push

function bh_git_push_force() {
  git push --force
}

function bh_git_push_ammend_all() {
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
    | sed 's/\// /g') | cut -f1) ] && printf FALSE || printf TRUE
}

# gitignore

function bh_git_gitignore_create() {
  : ${1?"Usage: ${FUNCNAME[0]} <contexts,..>"}
  curl -L -s "https://www.gitignore.io/api/$1"
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

# subfolders

function bh_git_subfolders_pull() {
  local cwd=$(pwd)
  local folder=$(pwd $0)
  cd $folder
  for i in $(find . -type d -iname .git | sed 's/\.git//g'); do
    cd "$folder/$i"
    if test -d .git; then
      bh_log_msg "pull on $i"
      git pull
    fi
    cd ..
  done
  cd $cwd
}

function bh_git_subfolders_reset_clean() {
  local cwd=$(pwd)
  local folder=$(pwd $1)
  cd $folder
  for i in $(find . -type d -iname .git | sed 's/\.git//g'); do
    cd "$folder/$i"
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

function bh_git_tag_move_to_corrent() {
  git tag -d $1
  git tag $1
  git push --force --tags 
}

function bh_git_tag_1dot0_move_to_corrent() {
  bh_git_tag_move_to_corrent 1.0
}

function bh_git_tag_remove_local_and_remote() {
  : ${1?"Usage: ${FUNCNAME[0]} <tagname>"}
  git tag -d $1
  git push origin :refs/tags/$1
}

# ammend

function bh_git_ammend_commit_all() {
  git commit -a --amend --no-edit
}

# open

function bh_git_open_gitg() {
  if ! test -d .git; then
    bh_log_error "There is no git repo in current folder"
    return
  fi
  gitg 2>/dev/null &
}

# open

function bh_git_log_history_file() {
  git log --follow -p --all --first-parent --remotes --reflog --author-date-order -- $1
}

# large_files

function bh_git_large_files_list() {
  git verify-pack -v .git/objects/pack/*.idx | sort -k 3 -n | tail -3
}
