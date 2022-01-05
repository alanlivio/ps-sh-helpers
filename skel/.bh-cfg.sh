# ----------------------------------------
# init vars
# ----------------------------------------
# ubuntu-only
BH_PKGS_SNAP=""
BH_PKGS_SNAP_CLASSIC=""
BH_PKGS_APT_UBUNTU=""
# linux-wsl-only
BH_PKGS_APT_WSL=""
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

# ----------------------------------------
# pkgs
# ----------------------------------------
# bash vscode
BH_PKGS_VSCODE+="timonwong.shellcheck "
BH_PKGS_VSCODE+="foxundermoon.shell-format "
# editing vscode
BH_PKGS_VSCODE+="henriiik.vscode-sort stkb.rewrap jianbingfang.dupchecker "
BH_PKGS_VSCODE+="tomsaunders-code.workspace-explorer "
# markdown vscode
BH_PKGS_VSCODE+="DavidAnson.vscode-markdownlint shd101wyy.markdown-preview-enhanced mervin.markdown-formatter "
# HTML/XML vscode
BH_PKGS_VSCODE+="dotjoshjohnson.xml redhat.vscode-yaml "
BH_PKGS_VSCODE+="mkaufman.HTMLHint "
# python DS
BH_PKGS_PYTHON+="wheel ipykernel numpy pandas scikit-learn mathplot matplotlib "
BH_PKGS_PYTHON+="nbdime " # jypter diff
# python vscode
BH_PKGS_PYTHON+="autopep8 pylama pylint "
BH_PKGS_VSCODE+="ms-python.python "

if $IS_WINDOWS_GITBASH; then
  BH_PKGS_VSCODE+="ms-vscode.powershell "
  BH_PKGS_VSCODE+="ms-vscode-remote.remote-wsl "
fi

# ----------------------------------------
# home dev folder
# ----------------------------------------
BH_DEV="$HOME/dev"
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

# ----------------------------------------
# home backups
# ----------------------------------------

# BKP_DOTFILES_DIR="$HOME/OneDrive/dotfiles"
# BH_DEV_REPOS="$HOME/.bashrc  $BKP_DOTFILES_DIR/.bashrc"
# BH_DEV_REPOS="$HOME/.profile  $BKP_DOTFILES_DIR/.bashrc"
