<h1 align="center"><img src="website/static/logo.svg" width="250"/></h1>

Cross-platform (Linux, Windows, macOS) bash helpers to configure OS (dark mode, disable animations), install/update software (python, vscode, docker, wsl, msys) and useful utilities (dotfiles, git, compress, curl). The project logo references the synthetic chemical element Bohrium, which also has the initials bh.

# How to install bash-helpers

The bash-helpers has two requirements: a `bash shell` and `git`. You may easily install using the scripts below.

macOS already has a bash shell.  
Run in a bash shell the script install/bh-on-mac.sh to install git and bash-helpers:

```bash
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/alanlivio/bash-helpers/master/install/bh-on-mac.sh)"
```

Ubuntu already has a bash.  
Run in a bash shell the script install/bh-on-ubu.shsh), to install git and bash-helpers:

```bash
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/alanlivio/bash-helpers/master/install/bh-on-ubu.sh)"
```

Windows do not have `bash shell` nor `git`.
Run in a powershell shell the script install/bh-on-win.ps1) to install git, GitBash, and bash-helpers:

```powershell
  Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/alanlivio/bash-helpers/master/install/bh-on-win.ps1'))
```

# helpers

### configure OS interface helpers

* `bh_gnome_sanity` (at ubuntu bash): enable dark mode, disable animations, clean taskbar (e.g. small icons, no search), uninstall pre-installed and not used apps (e.g. weather, news, calendar, solitaire)
* `bh_win_sanity` (at gitbash): enable dark mode, disable animations, clean dock (e.g. small icons)
* `bh_macos_sanity` (at bash): TODO

### install software helpers

* `bh_install_win_msys` (at windows GitBash): to install msys (Cygwin-based) with bash to build GNU-based win32 applications
* `bh_install_win_wsl` (at windows GitBash): to install WSL/Ubuntu (version 2, fixed home). This helper automates the process described in [Microsoft WSL Tutorial](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install). After running it, it requires restarting windows and running it again. When the Ubuntu app starts, you need to configure your username/password.
* See others `bh_install_win*` at ./win/
* See others `bh_install_ubu_*` at ./ubuntu/

### update/cleanup helpers

The helpers bellow can be run routinely. They install packages defined in `BH_PKGS_*` vars from ~/.bashrc or ~/.bh-cfg.sh, and also clean unused files/folders defined in `BH_HOME_CLEAN_UNUSED` var. Please see the vars examples in skel/.bh-cfg.sh.

* `bh_update_cleanup_mac` (at mac bash): BH_PKGS_BREW, BH_PKGS_PYTHON, BH_PKGS_VSCODE
* `bh_update_cleanup_ubu` (at ubuntu bash): BH_PKGS_APT_UBUNTU, BH_PKGS_PYTHON, BH_PKGS_VSCODE, BH_PKGS_SNAP, BH_PKGS_SNAP_CLASSIC
* `bh_update_cleanup_win` (at GitBash): BH_PKGS_WINGET, BH_PKGS_PYTHON, BH_PKGS_VSCODE
* `bh_update_cleanup_wsl` (at WSL bash): BH_PKGS_APT_WSL, BH_PKGS_PYTHON_WSL
* `bh_update_cleanup_msys` (at msys bash): BH_PKGS_MSYS, BH_PKGS_PYTHON_MSYS

### dotfiles/home managment helpers

* `bh_dotfiles_backup`: backup files/dirs defined in BH_DOTFILES_BKPS
* `bh_dotfiles_diff`: show diff files/dirs defined in BH_DOTFILES_BKPS
* `bh_dotfiles_install`: restore files/dirs defined in BH_DOTFILES_BKPS
* `bh_home_clean_unused`: clean files/dirs defined in array BH_HOME_CLEAN_UNUSED
* `bh_home_dev_folder_git_repos`: clone/update git repos defined in BH_DEV_REPOS

### curl helpers

* `bh_curl_get`: GET request to URL
* `bh_curl_post`: POST request to URL
* `bh_curl_post_json`: POST request to URL using JSON
* `bh_curl_fetch_to_dir`: get URL to parent dir

### forder helpers

* `bh_folder_sorted_by_size`: list folder sorted by items size
* `bh_folder_info`: list number of folder and files per extension
* `bh_folder_find_duplicated_pdf`: list duplicated pdf files in folder recursively

### others helpers

The helpers below are for specific commands. For the full list, see lib/ folder.

* `bh_android_*`: android helpers.
* `bh_cmake_*`: cmake helpers.
* `bh_compress_*`: compress helpers.
* `bh_cmake_*`: cmake helpers.
* `bh_diff_*`: diff helpers.
* `bh_docker_*`: docker helpers.
* `bh_ffmpeg_*`: ffmpeg helpers.
* `bh_flutter_*`: flutter helpers.
* `bh_gcc_*`: gcc helpers.
* `bh_git_*`: git helpers.
* `bh_meson_*`: meson helpers.
* `bh_mount_*`: mount helpers.
* `bh_npm_*`: npm helpers.
* `bh_pandoc_*`: pandoc helpers.
* `bh_pdf_*`: pdf helpers.
* `bh_python_*`: python helpers.
* `bh_vscode_*`: vscode helpers.
* `bh_rename_*`: rename helpers.
* `bh_wget_*`: wget helpers.
* `bh_youtubedl_*`: youtube-dl helpers.
* `bh_zip_*`: zip helpers.

# References

The projects bellow used as reference:

* https://github.com/wd5gnr/bashrc
* https://github.com/martinburger/bash-common-helpers
* https://github.com/jonathantneal/git-bash-helpers
* https://github.com/Bash-it/bash-it
* https://github.com/donnemartin/dev-setup
* https://github.com/aspiers/shell-env

And, particulary, these were reference for helpers on windows:

* https://github.com/adolfintel/windows10-Privacy
* https://gist.github.com/alirobe/7f3b34ad89a159e6daa1
* https://github.com/RanzigeButter/fyWin10/blob/master/fyWin10.ps1
* https://github.com/madbomb122/Win10Script/blob/master/Win10-Menu.ps1
* https://github.com/Sycnex/windows10Debloater/blob/master/windows10Debloater.ps1
* https://github.com/W4RH4WK/Debloat-windows-10/tree/master/scripts
