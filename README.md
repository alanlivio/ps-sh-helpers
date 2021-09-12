<h1 align="center"><img src="website/static/logo.svg" width="250"/></h1>

This project offers cross-plataform (linux, macOS, windows) bash helpers to: configure OS Desktop Shell (e.g., dark mode, disable animations), install software (e.g., python, vscode, docker, others bashs) and utilities (e.g., git, npm, compress, pdf, vscode, curl).
The project logo is a reference to the synthetic chemical element Bohrium, which also has the initials bh.

# How to install bash-helpers

The bash-helpers has two requeriments: a `bash shell` and `git` . You may easy install using the scripts bellow.

MacOS already has a bash shell.  
Run in a bash shell the script install/bh-on-mac.sh to install git and bash-helpers:

```bash
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/alanlivio/bash-helpers/master/install/bh-on-mac.sh)"
```

Ubuntu already has a bash.  
Run in a bash shell the script install/bh-on-ubuntu.shsh), to install git and bash-helpers:

```bash
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/alanlivio/bash-helpers/master/install/bh-on-ubuntu.sh)"
```

Windows do not has `bash shell` nor `git` .
Run in a powershell shell the script install/bh-on-win.ps1) to install git, GitBash, and bash-helpers:

```powershell
  Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/alanlivio/bash-helpers/master/install/bh-on-win.ps1'))
```

# helpers

### helpers for Desktop Shell sanity

* `bh_gnome_sanity` (at ubuntu bash): to configure Gnome Shell
* `bh_win_sanity` (at gitbash, run): to configure windows Shell

### helpers to install windows MSYS

* `bh_install_win_msys` (at windows GitBash): to install msys (Cygwin-based) with bash to build GNU-based win32 applications

### helpers to install windows WSL

* `bh_install_win_wsl` (at windows GitBash): to install WSL/Ubuntu (version 2, fixed home). This helper automate the process describred in [Microsoft WSL Tutorial](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install). After run, it requeres restart windows and run it again. When Ubuntu app started, you need configure your username/password.

### helpers for update/cleanup

The helpers bellow can be run routinely. They install packages defined in `BH_PKGS_*` vars from ~/.bashrc or ~/.bh-cfg.sh, and also clean unused files/folders defined in `BH_HOME_CLEAN_UNUSED` var. Please see the vars examples in skel/.bh-cfg.sh.

* `bh_update_cleanup_mac` (at mac bash): BH_PKGS_BREW, BH_PKGS_PYTHON, BH_PKGS_VSCODE
* `bh_update_cleanup_ubuntu` (at ubuntu bash): BH_PKGS_APT_UBUNTU, BH_PKGS_PYTHON, BH_PKGS_VSCODE, plus BH_PKGS_SNAP, BH_PKGS_SNAP_CLASSIC
* `bh_update_cleanup_win` (at GitBash): BH_PKGS_WINGET, BH_PKGS_PYTHON, BH_PKGS_VSCODE
* `bh_update_cleanup_wsl` (at WSL bash): BH_PKGS_APT_WSL, BH_PKGS_PYTHON_WSL
* `bh_update_cleanup_msys` (at msys bash): BH_PKGS_MSYS, BH_PKGS_PYTHON_MSYS

### helpers for home managment

* `bh_home_backup_save`: backup files/dirs defined in BH_HOME_BKPS
* `bh_home_backup_diff`: show diff files/dirs defined in BH_HOME_BKPS
* `bh_home_backup_restore`: restore files/dirs defined in BH_HOME_BKPS
* `bh_home_clean_unused`: clean files/dirs defined in array BH_HOME_CLEAN_UNUSED
* `bh_home_dev_folder_git_repos`: clone/update git repos defined in BH_DEV_REPOS

### helpers for curl

* `bh_curl_get`: GET request to URL
* `bh_curl_post`: POST request to URL
* `bh_curl_post_json`: POST request to URL using JSON
* `bh_curl_fetch_to_dir`: get URL to parent dir

### helpers for folder

* `bh_folder_sorted_by_size`: list folder sorted by items size
* `bh_folder_info`: list number of folder and files per extension
* `bh_folder_find_duplicated_pdf`: list duplicated pdf files in folder recursively

### others helpers

The helpers bellow used for specifc commands. For the full list, see lib/ folder.

* `bh_android_*`: android helpers. See full list at lib/android.sh
* `bh_cmake_*`: cmake helpers. See full list at lib/cmake.sh
* `bh_compress_*`: compress helpers. See full list at lib/compress.sh
* `bh_cmake_*`: cmake helpers. See full list at lib/cmake.sh
* `bh_diff_*`: diff helpers. See full list at lib/diff.sh
* `bh_docker_*`: docker helpers. See full list at lib/docker.sh
* `bh_ffmpeg_*`: ffmpeg helpers. See full list at lib/ffmpeg.sh
* `bh_flutter_*`: flutter helpers. See full list at lib/flutter.sh
* `bh_gcc_*`: gcc helpers. See full list at lib/gcc.sh
* `bh_git_*`: git helpers. See full list at lib/git.sh
* `bh_meson_*`: meson helpers. See full list at lib/meson.sh
* `bh_mount_*`: mount helpers. See full list at lib/mount.sh
* `bh_npm_*`: npm helpers. See full list at lib/npm.sh
* `bh_pandoc_*`: pandoc helpers. See full list at lib/pandoc.sh
* `bh_pdf_*`: pdf helpers. See full list at lib/pdf.sh
* `bh_python_*`: python helpers. See full list at lib/python.sh
* `bh_vscode_*`: vscode helpers. See full list at lib/vscode.sh
* `bh_rename_*`: rename helpers. See full list at lib/rename.sh
* `bh_wget_*`: wget helpers. See full list at lib/wget.sh
* `bh_youtubedl_*`: youtube-dl helpers. See full list at lib/youtubedl.sh
* `bh_zip_*`: zip helpers. See full list at lib/zip.sh

# References

Other github projects were used as reference:

* https://github.com/wd5gnr/bashrc
* https://github.com/martinburger/bash-common-helpers
* https://github.com/jonathantneal/git-bash-helpers
* https://github.com/Bash-it/bash-it
* https://github.com/donnemartin/dev-setup
* https://github.com/aspiers/shell-env

And, particulary, references for helpers on windows:

* https://github.com/adolfintel/windows10-Privacy
* https://gist.github.com/alirobe/7f3b34ad89a159e6daa1
* https://github.com/RanzigeButter/fyWin10/blob/master/fyWin10.ps1
* https://github.com/madbomb122/Win10Script/blob/master/Win10-Menu.ps1
* https://github.com/Sycnex/windows10Debloater/blob/master/windows10Debloater.ps1
* https://github.com/W4RH4WK/Debloat-windows-10/tree/master/scripts
