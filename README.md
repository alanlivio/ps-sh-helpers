<h1 align="center"><img src="logo.svg" width="250" onerror='this.style.display="none"'/></h1>

# bash-helpers

Multi-bash (win msys/gitbash/wsl, ubu, mac) helpers to easily install packages, setup os (dark mode, clean taskbar/clutter/unused), sync dotfiles, manage git repos, and more.
The project logo refers to the synthetic chemical element Bohrium, which also has BH's initials.

## Install

The bash-helpers project has two requirements: a `bash shell` and `git`. On win, you can use [GitForWindows](https://gitforwindows.org/) which install `gitabash`.
So, run on a `bash shell` with `git`,:
```bash
  git clone https://github.com/alanlivio/bash-helpers ~/.bh &&\
    echo "source ~/.bh/init.sh" >> ~/.bashrc &&\
    source ~/.bashrc
```

## helpers

### OS-any

home/dotfiles/pkgs helpers using `BH_*` vars from `~/.bashrc`, see examples at [skel/.bashrc](skel/.bashrc):

* `home_cleanup`: remove home files/dirs from BH_HOME_UNUSED_CLEAN. On win, hide dotfiles and BH_HOME_UNUSED_WIN_HIDE at home.
* `dotfiles_backup`: backup files/dirs defined in BH_DOTFILES.
* `dotfiles_diff`: show diff files/dirs defined in BH_DOTFILES.
* `dotfiles_install`: restore files/dirs defined in BH_DOTFILES.
* `pkgs_install` (at gitbash): install pkgs from BH_WIN_GET and BH_WIN_PIP.
* `pkgs_install` (at mac bash): install pkgs from BH_MAC_BREW and BH_MAC_PIP.
* `pkgs_install` (at msys bash): install pkgs from BH_MSYS2_PAC and BH_MSYS2_PIP.
* `pkgs_install` (at ubuntu bash): install pkgs from BH_UBU_APT and BH_UBU_PIP.
* `pkgs_install` (at WSL bash): install pkgs from BH_WSL_APT and BH_WSL_PIP.

decompress/folder/user:

* `decompress_from_url`: fetch and decompress to a given folder.
* `decompress`: decompress from multiple formats to a given folder.
* `folder_count_files`: count files in current folder
* `folder_count_files_recursive`: count files in current and sub folder
* `folder_find_duplicated_pdf`: list duplicated pdf files in dir recursively.
* `folder_sorted_by_size`: list dir sorted by item size.
* `user_sudo_nopasswd`:  disable password when calling sudo (user must be in sudores).

See more OS-independent helpers  [lib/os_any.bash](lib/os_any.bash) folder.

### linux

* `linux_mem_disk_cpu`: show used mem, disk, and cpu.
* `deb_install_url`: fetch and install a deb package.
* `gnome_sanity`: enable dark mode, disable animations, clean taskbar (e.g., small icons), uninstall pre-installed and not used apps (e.g., weather, news, calendar, solitaire).

See more linux helpers in [lib/os_linux.bash](lib/os_linux.bash).

### mac

* `mac_install_brew`: install brew package manager
* `mac_brew_install`: install a brew package
* `mac_brew_upgrade`: upgrade brew packages

See more mac helpers in [lib/os_mac.bash](lib/os_mac.bash).

### win

env/path:
* `win_env_add`: add variable to ENV.
* `win_env_show`: show ENV.
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
* `explorer_open_startmenu_user`: explorer open start menu folder for current user.
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

install others:

* `win_install_make`: winget install [gnumake](https://github.com/microsoft/winget-pkgs/tree/master/manifests/g/GnuWin32/Make) and add it to PATH.
* `win_install_miktex`: winget install [miktex](https://github.com/microsoft/winget-pkgs/tree/master/manifests/c/ChristianSchenk/MiKTeX) and add it to PATH.
* `win_install_ghostscript`: winget install [ghostscript](https://github.com/microsoft/winget-pkgs/tree/master/manifests/a/ArtifexSoftware/GhostScript) and add it to PATH.
* `win_install_ssh_client`: install [openssh client](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse?tabs=powershell).
* `win_install_android_sdkmanager_and_platform_tools`: install android [sdkmanager](https://developer.android.com/studio/command-line/sdkmanager) and [platform tools (adb)] (https://developer.android.com/studio/command-line/adb), and add them to PATH.
* `win_install_flutter`: install [flutter sdk](https://docs.flutter.dev/get-started/install/windows) and add it to PATH.


See more win helpers in [lib/os_win.bash](lib/os_win.bash).

### commands helpers

python:

* `pip_install`: install packages if not installed.
* `pip_upgrade_outdated`: upgrade outdated packages.
* `venv_create`: create a venv.
* `venv_activate_install`: load a venv.
* `python_setup_install`: install from a pkg folder with setup.py.
* `python_setup_upload_testpypi`: upload to testpypi from a pkg folder with setup.py.
* `python_setup_upload_pip`: upload to pip from a pkg folder with setup.py.

See others commands at: See more at: [adb.bash](lib/adb.bash), [ffmpeg.bash](lib/ffmpeg.bash), [ghostscript.bash](lib/ghostscript.bash), [gst.bash](lib/gst.bash), [lxc.bash](lib/lxc.bash), [pandoc.bash](lib/pandoc.bash), [pngquant.bash](lib/pngquant.bash), [python.bash](lib/python.bash), [ssh.bash](lib/ssh.bash), [wget.bash](lib/wget.bash), [zip.bash](lib/zip.bash), [cmake.bash](lib/cmake.bash), [flutter.bash](lib/flutter.bash), [git.bash](lib/git.bash), [latex.bash](lib/latex.bash), [meson.bash](lib/meson.bash), [pkg-config.bash](lib/pkg-config.bash), [ruby.bash](lib/ruby.bash), [tesseract.bash](lib/tesseract.bash), [youtube-dl.bash](lib/youtube-dl.bash).

## References

The projects below used as reference:

* <https://github.com/client9/shlib>
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

and, particularly, these were references for helpers on windows:

* <https://github.com/adolfintel/windows10-Privacy>
* <https://gist.github.com/alirobe/7f3b34ad89a159e6daa1>
* <https://github.com/RanzigeButter/fyWin10/blob/master/fyWin10.ps1>
* <https://github.com/madbomb122/Win10Script/blob/master/Win10-Menu.ps1>
* <https://github.com/Sycnex/windows10Debloater/blob/master/windows10Debloater.ps1>
* <https://github.com/W4RH4WK/Debloat-windows-10/tree/master/scripts>
