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

### update_clean and dotfiles helpers

The next helpers use variables from `~/.bashrc` to install software, clean unused files/dirs, and update repositories. 
Please see an example at [skel/.bashrc](https://github.com/alanlivio/bash-helpers/blob/master/skel/.bashrc).

* `update_clean` (at mac bash): install/update BH_MAC_BREW, BH_MAC_PY, clean files/dirs from BH_HOME_CLEAN_UNUSED
* `update_clean` (at ubuntu bash): install/update BH_UBU_APT, BH_UBU_PY,  clean files/dirs from BH_HOME_CLEAN_UNUSED
* `update_clean` (at GitBash): install/update BH_WIN_GET, BH_WIN_PY, clean files/dirs from BH_HOME_CLEAN_UNUSED
* `update_clean` (at WSL bash): install/update BH_WSL_APT, BH_WSL_PY, clean files/dirs from BH_HOME_CLEAN_UNUSED
* `update_clean` (at msys bash): install/update BH_MSYS_PAC, BH_MSYS_PY, clean files/dirs from BH_HOME_CLEAN_UNUSED
* `dotfiles_backup`: backup files/dirs defined in BH_DOTFILES
* `dotfiles_diff`: show diff files/dirs defined in BH_DOTFILES
* `dotfiles_install`: restore files/dirs defined in BH_DOTFILES

### ubu helpers

* `gnome_sanity` (at ubuntu bash): enable dark mode, disable animations, clean taskbar (e.g. small icons), uninstall pre-installed and not used apps (e.g. weather, news, calendar, solitaire)
* See others `ubu_install_*` at ./lib/ubu.bash

### win install helpers

* `win_install_msys` (at windows GitBash): to install msys (Cygwin-based) with bash to build GNU-based win32 applications
* `win_install_wsl` (at windows GitBash): to install WSL/Ubuntu (version 2, fixed home). This helper automates the process described in [Microsoft WSL Tutorial](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install). After running it, it requires restarting windows and running it again. When the Ubuntu app starts, you need to configure your username/password.
* See others `win_install_*` at ./lib/win.bash

### win sanity helpers

* `win_sanity_ui` (at gitbash): enable dark mode, disable animations, clean taskbar (e.g. small icons)
* `win_sanity_ctx_menu`: remove unused ctx menu
* `win_sanity_services`: remove unused ctx services
* `win_sanity_password_policy`: remove unused password policy
* `win_sanity_this_pc`: remove link folder on This PC 
* `win_sanity_all`: run all sanity above

### other win helpers

* `win_msys_same_home`: make msys uses win home
* `win_clean_trash`: clean trash
* `win_open_trash`: explorer open trash
* `win_restart_explorer`: explorer restart
* `win_open_tmp`:  explorer open win tmp
* `win_hide_home_dotfiles`: hide dotfiles at home folder
* `win_is_user_admin`: check if shell is admin
* `win_is_shell_eleveated`: check if shell is elevated
* `win_sysupdate`: update win
* `win_sysupdate_list`: list avaliable updates
* `win_feature_list_enabled`: list enabled features
* `win_feature_list_disabled`: list disabled features
* `win_feature_enable_ssh_server_bash`: add OpenSSH.Server capability
* `win_appx_list`:  Get-AppxPackage 
* `win_appx_install`: Add-AppxPackage
* `win_appx_uninstall`: Remove-AppxPackage
* `win_env_show`: show ENV
* `win_env_add`: add variable to ENV
* `win_path_show`: show PATH string
* `win_path_show_as_list`:  show PATH as list
* `win_path_add`: add dir to PATH
* `win_path_rm`: remove dir from PATH
* `win_get_list`: winget list
* `win_get_settings`: vscode open winget settings.json
* `win_get_upgrade`: winget upgrade
* `win_get_install`: winget install (check installed)

### others helpers

* `decompress_from_url`: fetch and decompress to folder
* `decompress`:  decompress from multiple formats
* `dir_find_duplicated_pdf`: list duplicated pdf files in dir recursively
* `dir_sorted_by_size`: list dir sorted by items size
* `user_sudo_nopasswd`:  disable password when call sudo (user must be in sudores)

See the full helpers at plugins/ and aliases/ folders.

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
