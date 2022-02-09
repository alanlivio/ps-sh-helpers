# ----------------------------------------
# .bhrc.sh skel
# ----------------------------------------
# home clean foders
BH_HOME_CLEAN_UNUSED=('Images' 'Movies' 'Public' 'Templates' 'Tracing' 'Videos' 'Music' 'Pictures' '.cache')
if $IS_UBU; then
  BH_HOME_CLEAN_UNUSED+=('Documents') # sensible data in Windows
elif $IS_WIN; then
  BH_HOME_CLEAN_UNUSED+=('Application Data' 'Cookies' 'Local Settings' 'Start Menu' '3D Objects' 'Contacts' 'Favorites' 'Links' 'MicrosoftEdgeBackups' 'My Documents' 'NetHood' 'PrintHood' 'Recent' 'Saved Games' 'Searches' 'SendTo')
fi

# ubu only
BH_PKGS_SNAP=""
BH_PKGS_SNAP_CLASSIC=""
BH_PKGS_APT_UBU=""
# wsl only
BH_PKGS_APT_WSL=""
BH_PKGS_APT_REMOVE_WSL=""
# win only
BH_PKGS_MSYS=""
BH_PKGS_CHOCO=""
BH_PKGS_WINGET=""
# msys only
BH_PKGS_MSYS=""
BH_PKGS_PY_MSYS=""
# mac only
BH_PKGS_BREW=""
# opt folder
BH_OPT_WIN="$HOME/AppData/Local/Programs"
BH_OPT_LINUX="$HOME/opt"
# dev folder
BH_DEV="$HOME/dev"
# cross os vscode/py/npm
BH_PKGS_VSCODE="timonwong.shellcheck foxundermoon.shell-format "
BH_PKGS_PY=""
BH_PKGS_NPM=""

# dotfiles backp
# BH_DOTFILES_BKP_DIR="$HOME/OneDrive/dotfiles"
# BH_DOTFILES_BKPS="$HOME/.bashrc $BH_DOTFILES_BKP_DIR/.bashrc "
# BH_DOTFILES_BKPS+="$HOME/.bhrc.sh $BH_DOTFILES_BKP_DIR/.bhrc.sh "

# dev/ repos
# BH_DEV_REPOS="bash-helpers git@github.com:alanlivio/bash-helpers "

# simple PS1
# export PS1="\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\] $ "
