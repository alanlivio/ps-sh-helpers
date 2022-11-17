source $HOME/.bh/init.sh

# home_clean
case $OSTYPE in
msys*)
  BH_HOME_WIN_HIDE_UNUSED=('Cookies' 'Picutres' '3D Objects' 'Contacts' 'Favorites' 'Links' 'MicrosoftEdgeBackups' 'NetHood' 'PrintHood' 'Recent' 'Saved Games' 'Searches' 'SendTo' 'ansel' 'Intel' 'IntelGraphicsProfiles' 'MicrosoftEdgeBackups')
  ;;
linux*)
  BH_HOME_RM_UNUSED=('Videos' 'Pictures' 'Documents')
  ;;
esac

# pkgs_install() at ubu
BH_UBU_APT="python "
BH_UBU_PY="autopep8 "
# pkgs_install() at mac
BH_MAC_BREW="vscode "
BH_MAC_PY="autopep8 "
# pkgs_install() at win
BH_WIN_GET="Microsoft.WindowsTerminal "
BH_WIN_PY="autopep8 "
# pkgs_install() at wsl
BH_WSL_APT="python "
BH_WSL_PY="autopep8 "
# pkgs_install() at msys
BH_MSYS_PAC="python "
BH_MSYS_PY="autopep8 "
# dotfiles_backup()
BH_DOTFILES_BKP_DIR="$HOME/Backup/dotfiles"
BH_DOTFILES="$HOME/.bashrc $BH_DOTFILES_BKP_DIR/.bashrc "
