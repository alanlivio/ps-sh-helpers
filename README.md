<h1 align="center"><img src="logo.svg" width="250" onerror='this.style.display="none"'/></h1>

# bash-helpers

Template to support you create multi-OS bash helpers (Win MSYS2/GitBash/WSL, Ubu, Mac). Useful to you organize your helpers in `OS-dependent` or `command-dependent`. The `OS-dependent` are loaded from `os_*.bash` files after testing `$OSTYPE` and may focus on OS setup (install packages, dark mode, clean taskbar/clutter/unused). The `command-dependent` are loaded from `lib/*.bash` after testing `type <command>`. 
The project logo refers to the synthetic chemical element Bohrium, which also has BH's initials.

## Install

The bash-helpers project has two requirements: a `bash shell` and `git`. So, run on a `bash shell` with `git`:
```bash
  git clone https://github.com/alanlivio/bash-helpers ~/.bh &&\
    echo "source ~/.bh/init.sh" >> ~/.bashrc &&\
    source ~/.bashrc
```

On Win, you run the above command at GitaBash installed with [GitForWindows](https://gitforwindows.org). If you also use WSL, you can share the same BH repo by doing a symbolic link to it with `ln -s /mnt/c/<user>/.bh ~/.bh`.

## OS-dependent samples

### os_any

* `pkgs_install`: install packages from BH_PKGS_WINGET, BH_PKGS_BREW, BH_PKGS_MSYS2, and BH_PKGS_APT, if Winget, brew, Pacman, and apt installed, respectively.
* `home_clean`: remove files/dirs defined in BH_HOME_CLEAN.
* `dotfiles_backup`: backup files/dirs defined in BH_DOTFILES.
* `dotfiles_diff`: show diff files/dirs defined in BH_DOTFILES.
* `dotfiles_install`: restore files/dirs defined in BH_DOTFILES.
* `decompress_from_url`: fetch and decompress to a given folder.
* `decompress`: extract from multiple formats to a given folder.
* `folder_count_files`: count files in the current folder
* `folder_count_files_recursive`: count files in the current and subfolder
* `folder_sorted_by_size`: list dir sorted by item size.
* `user_sudo_nopasswd`:  disable password when calling sudo (user must be in sudoers).

Some of the above helpers use `BH_*` vars from `~/.bashrc`, see examples at [skel/.bashrc](skel/.bashrc).
See more OS-independent helpers  [os_any.bash](os_any.bash) folder.

### os_ubu

* `ubu_update`: update ubuntu and all apt packages.
* `gnome_sanity`: enable dark mode, disable animations, clean taskbar (e.g., small icons), uninstall pre-installed and not used apps (e.g., weather, news, calendar, solitaire).
* `deb_install_url`: fetch and install a deb package.

See more Ubu helpers in [os_ubu.bash](os_ubu.bash).

### os_mac

* `mac_update`: update all brew packages
* `mac_install_brew`: install brew package manager

See more Mac helpers in [os_mac.bash](os_mac.bash).

### os_win

* `home_clean_win`: remove files/dirs defined in BH_HOME_CLEAN (even inside WSL), and hide from explorer dotfiles (.*) and others defined in BH_WIN_HIDE_HOME.
* `win_update`: update windows and all Winget packages.
* `start_open_recycle_bin`: explorer open trash folder.
* `start_open_startmenu_all`explorer opens the start menu folder for all users.
* `start_open_startmenu_user`: explorer opens the start menu folder for the current user.
* `start` (from GitBash or WSL): call cmd start or explorer.
* `win_env_add`: add variable to env variables.
* `win_env_show`: show env variables.
* `win_path_add`: add dir to PATH. It is a wrapper to [path_add.ps1](lib/ps1/path_add.ps1).
* `win_path_show_as_list`: show PATH as a list.
* `win_path_show`: show PATH string
* `win_sanity_password_policy`: remove password policy requirement. It is a wrapper to [path_add.ps1](lib/ps1/sanity_password_policy.ps1).
* `win_sanity_services_apps`: remove unused services and apps. It is a wrapper to [sanity_unused_services.ps1](lib/ps1/sanity_services_apps.ps1)
* `win_sanity_explorer`: remove link folders on This PC, disable recent files, etc. It is a wrapper to [sanity_explorer.ps1](lib/ps1/sanity_explorer.ps1).
* `win_sanity_ui`: enable dark mode, disable animations, and clean taskbar (e.g., small icons). It is a wrapper to [sanity_ui.ps1](lib/ps1/sanity_ui.ps1).
* `wsl_code_from_win` (at WSL): open the VSCode in the Win environment instead of WSL.
* `wsl_use_same_home` (at GitBash): make use uses win home. It is a wrapper to [wsl_use_same_home.ps1](lib/ps1/wsl_use_same_home.ps1).

See more helpers in [os_win.bash](os_win.bash).

## command-dependent samples

### Python

* `python_clean_cache`: clean cache
* `python_check_tensorflow`: check Tensorflow GPU support.
* `python_setup_install`: install from a pkg folder with setup.py.
* `python_setup_upload_testpypi`: upload to [testpypi repository](https://test.pypi.org/) from a pkg folder with setup.py.
* `python_setup_upload_pip`: upload to pip from a pkg folder with setup.py.
* `conda_env_create_from_enviroment_yml`: create env from environment.yml
* `conda_env_update_from_enviroment_yml`: update env from environment.yml

See more helpers in [lib/python.bash](lib/python.bash).

### Docker

* `docker_prune`: clean unused images and containers
* `docker_run_at_same_folder`: run, from an image, a command line using the current folder as the working folder

See more helpers in [lib/docker.bash](lib/docker.bash).

### others

See other commands at:
* [lib/adb.bash](lib/adb.bash)
* [lib/cmake.bash](lib/cmake.bash)
* [lib/ffmpeg.bash](lib/ffmpeg.bash)
* [lib/git.bash](lib/git.bash)
* [lib/gs.bash](lib/gs.bash)
* [lib/lxc.bash](lib/lxc.bash)
* [lib/meson.bash](lib/meson.bash)
* [lib/pandoc.bash](lib/pandoc.bash)
* [lib/wget.bash](lib/wget.bash)
* [lib/youtube-dl.bash](lib/youtube-dl.bash).

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
* <https://github.com/W4RH4WK/Debloat-windows-10/tree/master/scripts>
