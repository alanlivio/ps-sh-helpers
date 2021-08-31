BH_DEV="$HOME/dev"
# ubuntu-only
BH_PKGS_SNAP=""
BH_PKGS_SNAP_CLASSIC=""
BH_PKGS_APT_UBUNTU=" "
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
  'Images'
  'Movies'
  'Public'
  'Templates'
  'Tracing'
  'Videos'
  'Music'
  'Pictures'
)
if $IS_LINUX_UBUNTU; then
  BH_HOME_CLEAN_UNUSED+=(
    'Documents' # sensible data in Windows
  )
elif $IS_WINDOWS; then
  BH_HOME_CLEAN_UNUSED+=(
    'Application Data'
    'Cookies'
    'OpenVPN'
    'Local Settings'
    'Start Menu'
    '3D Objects'
    'Contacts'
    'Favorites'
    'Intel'
    'IntelGraphicsProfiles'
    'Links'
    'MicrosoftEdgeBackups'
    'My Documents'
    'NetHood'
    'PrintHood'
    'Recent'
    'Saved Games'
    'Searches'
    'SendTo'
  )
fi
BH_HOME_BKPS="$HOME/.bashrc $HOME/OneDrive/dotfiles/.bashrc"