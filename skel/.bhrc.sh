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
BH_UBU_SNAP="vscode "
BH_UBU_APT="python "
BH_UBU_PY="autopep8 "
BH_MAC_VSCODE="timonwong.shellcheck ms-python.python "
# mac only
BH_MAC_BREW="vscode "
BH_MAC_PY="autopep8 "
BH_MAC_VSCODE="timonwong.shellcheck ms-python.python "
# win only
BH_WIN_CHOCO="gsudo "
BH_WIN_GET="Microsoft.WindowsTerminal "
BH_WIN_PY="autopep8 "
BH_WIN_VSCODE="timonwong.shellcheck ms-python.python "
# wsl only
BH_WSL_APT="python "
BH_WSL_PY="autopep8 "
# msys only
BH_MSYS_PAC="python "
BH_MSYS_PY="autopep8 "
# opt folder
if $IS_WIN; then
  BH_OPT="$HOME/opt"
else
  BH_OPT="$HOME/AppData/Local/Programs"
fi
# dev folder
BH_DEV="$HOME/dev"
# cross os vscode/py/npm
BH_WIN_VSCODE="timonwong.shellcheck foxundermoon.shell-format "
BH_WIN_PY="autopep8 "

# dotfiles backp
# BH_DOTFILES_BKP_DIR="$HOME/OneDrive/dotfiles"
# BH_DOTFILES="$HOME/.bashrc $BH_DOTFILES_BKP_DIR/.bashrc "
# BH_DOTFILES+="$HOME/.bhrc.sh $BH_DOTFILES_BKP_DIR/.bhrc.sh "

# dev/ repos
# BH_DEV_REPOS="bash-helpers git@github.com:alanlivio/bash-helpers "

# simple PS1
# export PS1="\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\] $ "
