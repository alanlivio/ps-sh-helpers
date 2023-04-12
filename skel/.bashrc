source $HOME/.bh/init.sh

# home_clean
case $OSTYPE in
msys*)
  BH_HOME_UNUSED_WIN_HIDE=('Cookies' 'Picutres' '3D Objects' 'Contacts' 'Favorites' 'Links' 'MicrosoftEdgeBackups' 'NetHood' 'PrintHood' 'Recent' 'Saved Games' 'Searches' 'SendTo' 'ansel' 'Intel' 'IntelGraphicsProfiles' 'MicrosoftEdgeBackups')
  ;;
linux*)
  BH_HOME_UNUSED_CLEAN=('Videos' 'Pictures' 'Documents')
  ;;
esac

# pkgs_install()
BH_PKGS_APT="python "
BH_PKGS_BREW="vscode "
BH_PKGS_WINGET="Microsoft.WindowsTerminal "
BH_PKGS_MSYS2="python "
# dotfiles_backup()
BH_DOTFILES_BKP_DIR="$HOME/Backup/dotfiles"
BH_DOTFILES="$HOME/.bashrc $BH_DOTFILES_BKP_DIR/.bashrc "
