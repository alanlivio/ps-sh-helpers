# ubu_update
BH_PKGS_APT="python "
# mac_update
BH_PKGS_BREW="vscode "
# win_update
BH_PKGS_WINGET="Microsoft.WindowsTerminal "
# dotfiles_backup
BH_DOTFILES_BKP_DIR="$HOME/Backup/dotfiles"
BH_DOTFILES="$HOME/.bashrc $BH_DOTFILES_BKP_DIR/.bashrc "
# download and setup bash-helpers
BH="$HOME/.bh/"
BH_INIT="$HOME/.bh/init.sh"
if ! test -d $BH; then git clone https://github.com/alanlivio/bash-helpers $BH; fi
if test -f $BH_INIT; then source $BH_INIT; fi