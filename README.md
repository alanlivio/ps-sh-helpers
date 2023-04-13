<h1 align="center"><img src="logo.svg" width="250" onerror='this.style.display="none"'/></h1>

# bash-helpers

Template to create multi-OS bash helpers (win msys/gitbash/wsl, ubu, mac). Useful to you organize your helpers in `OS-dependent` or `command-dependent`. The `OS-dependent` are loaded from `os_*.bash` files after testing `$OSTYPE` and may focus on OS setup (install pkgs, dark mode, clean taskbar/clutter/unused). The `command-dependent` are loaded from `lib/*.bash` after testing `type <command>`. 
The project logo refers to the synthetic chemical element Bohrium, which also has BH's initials.

## Install

The bash-helpers project has two requirements: a `bash shell` and `git`. On win, you can use [GitForWindows](https://gitforwindows.org), which installs `gitabash`.

So, run on a `bash shell` with `git`,:
```bash
  git clone https://github.com/alanlivio/bash-helpers ~/.bh &&\
    echo "source ~/.bh/init.sh" >> ~/.bashrc &&\
    source ~/.bashrc
```

## OS-dependent samples

### os_any

home/dotfiles/pkgs helpers using `BH_*` vars from `~/.bashrc`, see examples at [skel/.bashrc](skel/.bashrc):

* `pkgs_install`: install pkgs from BH_PKGS_WINGET, BH_PKGS_BREW, BH_PKGS_MSYS2, and BH_PKGS_APT, if winget, brew, pacman, and apt installed, respectively.
* `home_cleanup`: remove home files/dirs from BH_HOME_UNUSED_CLEAN. On win, hide dotfiles and BH_HOME_UNUSED_WIN_HIDE at home.
* `dotfiles_backup`: backup files/dirs defined in BH_DOTFILES.
* `dotfiles_diff`: show diff files/dirs defined in BH_DOTFILES.
* `dotfiles_install`: restore files/dirs defined in BH_DOTFILES.

decompress/folder/user:

* `decompress_from_url`: fetch and decompress to a given folder.
* `decompress`: decompress from multiple formats to a given folder.
* `folder_count_files`: count files in current folder
* `folder_count_files_recursive`: count files in current and sub folder
* `folder_sorted_by_size`: list dir sorted by item size.
* `user_sudo_nopasswd`:  disable password when calling sudo (user must be in sudores).

See more OS-independent helpers  [os_any.bash](os_any.bash) folder.

### os_ubu

* `gnome_sanity`: enable dark mode, disable animations, clean taskbar (e.g., small icons), uninstall pre-installed and not used apps (e.g., weather, news, calendar, solitaire).
* `deb_install_url`: fetch and install a deb package.

See more linux helpers in [os_ubu.bash](os_ubu.bash).

### os_mac

* `mac_install_brew`: install brew package manager
* `mac_brew_install`: install a brew package
* `mac_brew_upgrade`: upgrade brew packages

See more mac helpers in [os_mac.bash](os_mac.bash).

### os_win

env/path:
* `win_env_add`: add variable to env variables.
* `win_env_show`: show env variables.
* `win_path_show_as_list`: show PATH as a list.
* `win_path_show`: show PATH string
* `win_path_add`: add dir to PATH. It is a wrapper to [path_add.ps1](lib/ps1/path_add.ps1).

winget:
* `winget_install`: winget install packages if not installed.
* `winget_list`: winget list packages.
* `winget_upgrade_all`: winget upgrade all packages.

explorer:
* `explorer_hide_home_dotfiles`: hide dotfiles at home folder.
* `explorer_restart`: restart explorer.
* `explorer_open_recycle_bin`: explorer open trash folder.
* `explorer_open_startmenu_user`: explorer opens start menu folder for the  current user.
* `explorer_open_startmenu_all`: explorer open start menu folder for all users.

sanity:
* `win_sanity_ctx_menu`: remove unused context menu. It is a wrapper to [sanity_ctx_menu.ps1](lib/ps1/sanity_ctx_menu.ps1)
* `win_sanity_password_policy`: remove password policy requirement. It is a wrapper to [path_add.ps1](lib/ps1/sanity_password_policy.ps1).
* `win_sanity_services`: remove unused context services. It is a wrapper to [sanity_services.ps1](lib/ps1/sanity_services.ps1)
* `win_sanity_this_pc`: remove link folders on This PC. It is a wrapper to [sanity_this_pc.ps1](lib/ps1/sanity_this_pc.ps1).
* `win_sanity_ui` (at gitbash): enable dark mode, disable animations, and clean taskbar (e.g., small icons). It is a wrapper to [sanity_ui.ps1](lib/ps1/sanity_ui.ps1).
* `win_sys_upgrade`: update win.

wsl:
* `win_install_wsl` (at gitbash): to install WSL/Ubuntu automating the process described in [Microsoft WSL Tutorial](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install). After running it, it requires restarting win and running it again. When the Ubuntu app starts, you must configure your username/password. It is a wrapper to [wsl_install.ps1](lib/ps1/wsl_install.ps1).
* `wsl_use_same_home` (at gitbash): make use uses win home. It is a wrapper to [wsl_use_same_home.ps1](lib/ps1/wsl_use_same_home.ps1).
* `wsl_code_from_win` (at wsl): open vscode in win environment instead of wsl (useful with use wsl default bash).

See more win helpers in [os_win.bash](os_win.bash).

## command-dependent samples

### python

* `pip_install`: install packages if not installed.
* `pip_upgrade_outdated`: upgrade outdated packages.
* `venv_create`: create a venv.
* `venv_activate_install`: load a venv.
* `python_setup_install`: install from a pkg folder with setup.py.
* `python_setup_upload_testpypi`: upload to testpypi from a pkg folder with setup.py.
* `python_setup_upload_pip`: upload to pip from a pkg folder with setup.py.

### others

See others commands at: 
* [adb.bash](lib/adb.bash)
* [cmake.bash](lib/cmake.bash)
* [ffmpeg.bash](lib/ffmpeg.bash)
* [git.bash](lib/git.bash)
* [gs.bash](lib/gs.bash)
* [lxc.bash](lib/lxc.bash)
* [meson.bash](lib/meson.bash)
* [pandoc.bash](lib/pandoc.bash)
* [python.bash](lib/python.bash)
* [wget.bash](lib/wget.bash)
* [youtube-dl.bash](lib/youtube-dl.bash).

## References

This project takes inspiration from:

* <https://github.com/Bash-it/bash-it>
* <https://github.com/milianw/shell-helpers>
* <https://github.com/wd5gnr/bashrc>
* <https://github.com/martinburger/bash-common-helpers>
* <https://github.com/jonathantneal/git-bash-helpers>
* <https://github.com/donnemartin/dev-setup>
* <https://github.com/aspiers/shell-env>
* <https://github.com/nafigator/bash-helpers>
* <https://github.com/TiSiE/BASH.helpers>
* <https://github.com/midwire/bash.env>
* <https://github.com/e-picas/bash-library>
* <https://github.com/awesome-windows11/windows11>
* <https://github.com/99natmar99/Windows-11-Fixer>
* <https://github.com/adolfintel/windows10-Privacy>
* <https://gist.github.com/alirobe/7f3b34ad89a159e6daa1>
* <https://github.com/RanzigeButter/fyWin10/blob/master/fyWin10.ps1>
* <https://github.com/madbomb122/Win10Script/blob/master/Win10-Menu.ps1>
* <https://github.com/Sycnex/windows10Debloater/blob/master/windows10Debloater.ps1>
* <https://github.com/W4RH4WK/Debloat-windows-10/tree/master/scripts>
