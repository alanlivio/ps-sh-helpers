# ----------------------------------------
# init vars
# ----------------------------------------
# ubu only
BH_PKGS_SNAP=""
BH_PKGS_SNAP_CLASSIC=""
BH_PKGS_APT_UBUNTU=""
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
BH_PKGS_VSCODE=""
BH_PKGS_PY=""
BH_PKGS_NPM=""
# vscode bash
BH_PKGS_VSCODE+="timonwong.shellcheck "
BH_PKGS_VSCODE+="foxundermoon.shell-format "

# ----------------------------------------
# dev repos
# ----------------------------------------
# BH_DEV_REPOS="parent/folder/name1/in/BH_DEV <REPO_URL_1>"
# BH_DEV_REPOS="parent/folder/name1/in/BH_DEV <REPO_URL_2>"
# BH_DEV_REPOS="parent/folder/name2/in/BH_DEV <REPO_URL_3>"

# ----------------------------------------
# home clean unused
# ----------------------------------------
BH_HOME_CLEAN_UNUSED=(
  'Images'
  'Movies'
  'Public'
  'Templates'
  'Tracing'
  'Videos'
  'Music'
  'Pictures'
  '.cache'
)
if $IS_LINUX_UBU; then
  BH_HOME_CLEAN_UNUSED+=(
    'Documents' # sensible data in Windows
  )
elif $IS_WIN; then
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

# ----------------------------------------
# home backups
# ----------------------------------------

# BH_DOTFILES_BKP_DIR="$HOME/OneDrive/dotfiles"
# BH_DOTFILES_BKPS="$HOME/.bashrc $BH_DOTFILES_BKP_DIR/.bashrc "
# BH_DOTFILES_BKPS+="$HOME/.bh-cfg.sh $BH_DOTFILES_BKP_DIR/.bh-cfg.sh "

# ----------------------------------------
# dev/ git repos
# ----------------------------------------

# BH_DEV_REPOS="sites git@github.com:alanlivio/alanlivio.github.io.git "
