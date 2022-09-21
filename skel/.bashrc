source $HOME/.bh/init.sh

# pkgs_install() clean folder
BH_HOME_CLEAN_UNUSED=('Images' 'Movies' 'Public' 'Templates' 'Tracing' 'Videos' 'Pictures' '.cache')
case $OSTYPE in
msys*)
  BH_HOME_CLEAN_UNUSED+=('Application Data' 'Cookies' 'Local Settings' 'Start Menu' '3D Objects' 'Contacts' 'Favorites' 'Links' 'MicrosoftEdgeBackups' 'My Documents' 'NetHood' 'PrintHood' 'Recent' 'Saved Games' 'Searches' 'SendTo')
  ;;
linux*)
  BH_HOME_CLEAN_UNUSED+=('Documents') # sensible data in Windows
  ;;
esac
# pkgs_install() at ubu
BH_UBU_SNAP="vscode "
BH_UBU_APT="python "
BH_UBU_PY="autopep8 "
# pkgs_install() at mac
BH_MAC_BREW="vscode "
BH_MAC_PY="autopep8 "
# pkgs_install() at win
BH_WIN_CHOCO="gsudo "
BH_WIN_GET="Microsoft.WindowsTerminal "
BH_WIN_PY="autopep8 "
# pkgs_install() at wsl
BH_WSL_APT="python "
BH_WSL_PY="autopep8 "
# pkgs_install() at msys
BH_MSYS_PAC="python "
BH_MSYS_PY="autopep8 "
# dotfiles_backp()
BH_DOTFILES_BKP_DIR="$HOME/Backup/dotfiles"
BH_DOTFILES="$HOME/.bashrc $BH_DOTFILES_BKP_DIR/.bashrc "
