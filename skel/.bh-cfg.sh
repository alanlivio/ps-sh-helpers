BH_DEV="$HOME/dev"
# ubuntu-only
BH_PKGS_SNAP=""
BH_PKGS_SNAP_CLASSIC=""
BH_PKGS_APT_UBUNTU=" "
BH_PKGS_APT_REMOVE_UBUNTU=""
# linux-wsl-only
BH_PKGS_APT_WSL=" "
BH_PKGS_APT_REMOVE_WSL=""
# win-only
BH_PKGS_MSYS=""
BH_PKGS_CHOCO=""
BH_PKGS_WINGET=""
BH_PKGS_PYTHON_MSYS=""
# mac-only
BH_PKGS_BREW=""
# others
BH_PKGS_VSCODE=""
BH_PKGS_NPM=""
BH_PKGS_PYTHON=""
# clean folder
BH_HOME_CLEAN_UNUSED=(
  'Public'
  'Templates'
  'Tracing'
)
BH_HOME_BKPS="$HOME/.bashrc $HOME/OneDrive/dotfiles/.bashrc"