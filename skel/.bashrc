source $HOME/.bh/init.sh

# home_clean_unused()
BH_HOME_CLEAN_UNUSED=('Images' 'Movies' 'Public' 'Templates' 'Tracing' 'Videos' 'Music' 'Pictures' '.cache')

case $OSTYPE in
msys*)
  BH_HOME_CLEAN_UNUSED+=('Application Data' 'Cookies' 'Local Settings' 'Start Menu' '3D Objects' 'Contacts' 'Favorites' 'Links' 'MicrosoftEdgeBackups' 'My Documents' 'NetHood' 'PrintHood' 'Recent' 'Saved Games' 'Searches' 'SendTo')
  ;;
linux*)
  BH_HOME_CLEAN_UNUSED+=('Documents') # sensible data in Windows
  ;;
esac
# ubu_update_clean()
BH_UBU_SNAP="vscode "
BH_UBU_APT="python "
BH_UBU_PY="autopep8 "
BH_MAC_VSCODE="timonwong.shellcheck ms-python.python "
# mac_update_clean()
BH_MAC_BREW="vscode "
BH_MAC_PY="autopep8 "
BH_MAC_VSCODE="timonwong.shellcheck ms-python.python "
# win_update_clean()
BH_WIN_CHOCO="gsudo "
BH_WIN_GET="Microsoft.WindowsTerminal "
BH_WIN_PY="autopep8 "
BH_WIN_VSCODE="timonwong.shellcheck ms-python.python foxundermoon.shell-format "
BH_WIN_PY="autopep8 "
# wsl_update_clean()
BH_WSL_APT="python "
BH_WSL_PY="autopep8 "
# msys_update_clean()
BH_MSYS_PAC="python "
BH_MSYS_PY="autopep8 "
# dotfiles_backp()
BH_DOTFILES_BKP_DIR="$HOME/Backup/dotfiles"
BH_DOTFILES="$HOME/.bashrc $BH_DOTFILES_BKP_DIR/.bashrc "
