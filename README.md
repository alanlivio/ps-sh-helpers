<h1 align="center"><img src="docs/mkdocs/logo.svg" width="250" onerror='this.style.display="none"'/></h1>

# bash-helpers

Cross-OS bash helpers for installation (wsl/msys, adb, flutter, ffmpeg), setup (dark mode, clean taskbar/clutter/unused), update python/vscode pkgs, sync dotfiles, common git calls, and more. 
The project logo refers to the synthetic chemical element Bohrium, which also has the initials bh.

## Install

The bash-helpers project has two requirements: a `bash shell` and `git`. Particularly on windows, they can be installed using [GitForWindows](https://gitforwindows.org/) (you may install it running [install-gitforwindows-and-wt.ps1](https://github.com/alanlivio/bash-helpers/blob/master/lib/win/install-gitforwindows-and-wt.ps1) on powershell). 

Then, on the ubu/mac/GitForWindows `bash shell` with `git`, run:
```bash
  git clone https://github.com/alanlivio/bash-helpers ~/.bh &&\
    echo "source ~/.bh/init.sh" >> ~/.bashrc &&\
    source ~/.bashrc
```

## helpers

### configure OS interface helpers

* `gnome_sanity` (at ubuntu bash): enable dark mode, disable animations, clean taskbar (e.g. small icons), uninstall pre-installed and not used apps (e.g. weather, news, calendar, solitaire)
* `win_sanity_ui` (at gitbash): enable dark mode, disable animations, clean taskbar (e.g. small icons)

### install software helpers

* `win_install_msys` (at windows GitBash): to install msys (Cygwin-based) with bash to build GNU-based win32 applications
* `win_install_wsl` (at windows GitBash): to install WSL/Ubuntu (version 2, fixed home). This helper automates the process described in [Microsoft WSL Tutorial](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install). After running it, it requires restarting windows and running it again. When the Ubuntu app starts, you need to configure your username/password.
* See others `win_install_*` at ./lib/win.bash
* See others `ubu_install_*` at ./lib/ubu.bash

### update/cleanup/dotfiles/repos

The helpers below can be run routinely. They use variables at `~/.bhrc.sh` (or `~/.bashrc`) to install software, clean unused files/dirs, and update repositories. Please see examples in [skel/.bhrc.sh](https://github.com/alanlivio/bash-helpers/blob/master/skel/.bhrc.sh).

* `setup_mac` (at mac bash): install/update BH_MAC_BREW, BH_MAC_PY, BH_MAC_VSCODE
* `setup_ubu` (at ubuntu bash): install/update BH_UBU_APT, BH_UBU_PY, BH_UBU_VSCODE, BH_UBU_SNAP
* `setup_win` (at GitBash): install/update BH_WIN_GET, BH_WIN_PY, BH_WIN_VSCODE
* `setup_wsl` (at WSL bash): install/update BH_WSL_APT, BH_WSL_PY
* `setup_msys` (at msys bash): install/update BH_MSYS_PAC, BH_MSYS_PY
* `dotfiles_backup`: backup files/dirs defined in BH_DOTFILES
* `dotfiles_diff`: show diff files/dirs defined in BH_DOTFILES
* `dotfiles_install`: restore files/dirs defined in BH_DOTFILES
* `home_clean_unused`: clean files/dirs defined in array BH_HOME_CLEAN_UNUSED
* `dev_dir_git_repos`: clone/update git repos defined in BH_DEV_REPOS

### curl helpers

* `curl_get`: GET request to URL
* `curl_post`: POST request to URL
* `curl_post_json`: POST request to URL using JSON
* `curl_fetch_to_dir`: get URL to parent dir

### forder helpers

* `dir_sorted_by_size`: list dir sorted by items size
* `dir_info`: list number of dir and files per extension
* `dir_find_duplicated_pdf`: list duplicated pdf files in dir recursively

### others helpers

The helpers below are for cross-OS commands. For the full list, see lib/.

* `adb_*`: adb helpers.
* `cmake_*`: cmake helpers.
* `docker_*`: docker helpers.
* `ffmpeg_*`: ffmpeg helpers.
* `flutter_*`: flutter helpers.
* `gcc_*`: gcc helpers.
* `git_*`: git helpers.
* `ghostscript_*`: ghostscript helpers (for pdf).
* `meson_*`: meson helpers.
* `npm_*`: npm helpers.
* `pandoc_*`: pandoc helpers.
* `pdflatex_*`: pdflatex helpers.
* `pkg-config_*`: pkg-config helpers.
* `py_*`: python helpers.
* `ruby_*`: ruby helpers.
* `ssh_*`: ssh helpers.
* `tesseract_*`: tesseract helpers.
* `vscode_*`: vscode helpers.
* `wget_*`: wget helpers.
* `youtubedl_*`: youtube-dl helpers.
* `zip_*`: zip helpers.

## References

The projects bellow used as reference:

* <https://github.com/milianw/shell-helpers>
* <https://github.com/wd5gnr/bashrc>
* <https://github.com/martinburger/bash-common-helpers>
* <https://github.com/jonathantneal/git-bash-helpers>
* <https://github.com/Bash-it/bash-it>
* <https://github.com/donnemartin/dev-setup>
* <https://github.com/aspiers/shell-env>
* <https://github.com/nafigator/bash-helpers>
* <https://github.com/martinburger/bash-common-helpers>
* <https://github.com/TiSiE/BASH.helpers>
* <https://jonlabelle.com/snippets/view/shell/bash-date-helper-functions>
* <https://jonlabelle.com/snippets/tag/bash>
* <https://github.com/midwire/bash.env>
* <https://github.com/e-picas/bash-library>
* <https://github.com/cyberark/bash-lib>
* <https://www.conjur.org/blog/stop-bashing-bash>

And, particulary, these were reference for helpers on windows:

* <https://github.com/adolfintel/windows10-Privacy>
* <https://gist.github.com/alirobe/7f3b34ad89a159e6daa1>
* <https://github.com/RanzigeButter/fyWin10/blob/master/fyWin10.ps1>
* <https://github.com/madbomb122/Win10Script/blob/master/Win10-Menu.ps1>
* <https://github.com/Sycnex/windows10Debloater/blob/master/windows10Debloater.ps1>
* <https://github.com/W4RH4WK/Debloat-windows-10/tree/master/scripts>
