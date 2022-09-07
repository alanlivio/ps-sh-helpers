<h1 align="center"><img src="logo.svg" width="250" onerror='this.style.display="none"'/></h1>

# bash-helpers

Cross-OS bash helpers for installation (wsl/msys, adb, flutter, ffmpeg), setup (dark mode, clean taskbar/clutter/unused), update python/vscode packages, sync dotfiles, common git calls, and more. 
The project logo refers to the synthetic chemical element Bohrium, which also has the initials bh.

## Install

The bash-helpers project has two requirements: a `bash shell` and `git`. Particularly on windows, they can be installed using [GitForWindows](https://gitforwindows.org/) (you may install it running [install_gitbash.ps1](https://github.com/alanlivio/bash-helpers/blob/master/lib/ps1/install_gitbash.ps1) on PowerShell). 

Then, on the ubu/mac/GitForWindows `bash shell` with `git`, run:
```bash
  git clone https://github.com/alanlivio/bash-helpers ~/.bh &&\
    echo "source ~/.bh/init.sh" >> ~/.bashrc &&\
    source ~/.bashrc
```

## helpers

### using BH_* variables

The next helpers use variables from `~/.bashrc`. Please see an example at [skel/.bashrc](https://github.com/alanlivio/bash-helpers/blob/master/skel/.bashrc).

* `dotfiles_backup`: backup files/dirs defined in BH_DOTFILES
* `dotfiles_diff`: show diff files/dirs defined in BH_DOTFILES
* `dotfiles_install`: restore files/dirs defined in BH_DOTFILES
* `home_cleanup`: remove home files/dirs from BH_HOME_CLEAN_UNUSED and, at win, hide dotfiles.
* `update_clean_os` (at GitBash): install BH_WIN_GET, BH_WIN_PY
* `update_clean_os` (at mac bash): install BH_MAC_BREW, BH_MAC_PY
* `update_clean_os` (at msys bash): install BH_MSYS_PAC, BH_MSYS_PY
* `update_clean_os` (at ubuntu bash): install BH_UBU_APT, BH_UBU_PY
* `update_clean_os` (at WSL bash): install BH_WSL_APT, BH_WSL_PY

### bash/dir/curl helpers

* `bash_sudo_nopasswd`:  disable password when calling sudo (user must be in sudores)
* `decompress_from_url`: fetch and decompress to a given folder
* `decompress`: decompress from multiple formats
* `dir_find_duplicated_pdf`: list duplicated pdf files in dir recursively
* `dir_sorted_by_size`: list dir sorted by items size

### gnome helpers

* `gnome_sanity` (at ubuntu bash): enable dark mode, disable animations, clean taskbar (e.g. small icons), uninstall pre-installed and not used apps (e.g. weather, news, calendar, solitaire)

### win helpers

* `win_env_add`: add variable to ENV
* `win_env_show`: show ENV
* `win_get_install`: winget install
* `win_get_list`: winget list
* `win_get_settings`: vscode open winget settings.json
* `win_get_upgrade`: winget upgrade
* `win_hide_home_dotfiles`: hide dotfiles at home folder`win_is_shell_eleveated`check if the shell is elevated`win_is_user_admin`check if the shell is admin
* `win_open_tmp`:  explorer open win temp dir
* `win_open_trash`: explorer open trash
* `win_path_add`: add dir to PATH
* `win_path_rm`: remove dir from PATH
* `win_path_show_as_list`:  show PATH as list
* `win_path_show`: show PATH string
* `win_restart_explorer`: explorer restart
* `win_sanity_all`: run all sanity above
* `win_sanity_ctx_menu`: remove unused context menu
* `win_sanity_password_policy`: remove password policy requirement
* `win_sanity_services`: remove unused context services
* `win_sanity_this_pc`: remove link folder on This PC 
* `win_sanity_ui` (at gitbash): enable dark mode, disable animations, clean taskbar (e.g. small icons)
* `win_sys_update`: update win

### win setup of MSYS2/WSL helpers

* `win_install_wsl` (at windows GitBash): to install WSL/Ubuntu automating the process described in [Microsoft WSL Tutorial](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install). After running it, it requires restarting windows and running it again. When the Ubuntu app starts, you need to configure your username/password.
* `win_wsl_same_home`: make use uses win home
* `win_install_msys` (at windows GitBash): to install [MSYS2](https://www.msys2.org/) useful to build GNU-based win32 applications
* `win_msys_same_home`: make MSYS2 uses win home

### python helpers

* `python_upgrade`: upgrade a given list of python packages 
* `python_install`: install a given list of python packages 
* `python_uninstall`: uninstall a given list of python packages
* `python_venv_create`: create a venv
* `python_venv_load`: load a venv
* `python_setup_install_user`: install from a pkg folder with setup.py
* `python_setup_upload_testpypi`: upload to testpypi from a pkg folder with setup.py
* `python_setup_upload_pip`: upload to pip from a pkg folder with setup.py

### other helpers

See the full helpers at plugins/ and aliases/ folders.

## References

The projects below used as reference:

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

And, particularly, these were references for helpers on windows:

* <https://github.com/adolfintel/windows10-Privacy>
* <https://gist.github.com/alirobe/7f3b34ad89a159e6daa1>
* <https://github.com/RanzigeButter/fyWin10/blob/master/fyWin10.ps1>
* <https://github.com/madbomb122/Win10Script/blob/master/Win10-Menu.ps1>
* <https://github.com/Sycnex/windows10Debloater/blob/master/windows10Debloater.ps1>
* <https://github.com/W4RH4WK/Debloat-windows-10/tree/master/scripts>
