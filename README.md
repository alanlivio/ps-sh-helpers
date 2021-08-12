<h1 align="center">bash-helpers</h1>

This project offers cross-plataform (linux, macOS, windows) bash helpers to: configure OS (e.g., disable unused services/features/apps, dark mode), install software (e.g., git, python, vscode) and utilities (e.g., install software, git, pdf, compression).

# How to install

To enable bash-helpers (windows git-bash, macOS bash, MSYS bash, WSL bash), you can it as  a [Bash Startup File](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html). To do that, run the followings commands for fetch rc.sh and load at `~/.bashrc` :

```bash
  git clone https://github.com/alanlivio/bash-helpers.git ~/.bh
    echo "source ~/.bh/rc.sh" >> ~/.bashrc &&\
    source ~/.bashrc
  ```

# Usage

## setup Gnome-based Ubuntu

1. `bh_setup_ubuntu`: configure Gnome (e.g., disable unused services/features/apps, dark mode) and install essential software (e.g., git, wget, curl, python, vscode).
2. `bh_update_clean` (run routinely): configure/upgrade packges using variables (PKGS_APT, PKGS_PYTHON, PKGS_SNAP, PKGS_SNAP_CLASSIC, PKGS_REMOVE_APT) in ~/.bashrc or ~/.bh-cfg.sh, and cleanup.

## setup macOS

1. `bh_setup_mac`: install essential software (brew, bash last version, python, vscode)
2. `bh_update_clean` (run routinely): configure/upgrade packges using variables (PKGS_BREW) in ~/.bashrc or ~/.bh-cfg.sh, and cleanup.

## setup Windows for common (non-dev) users

1. `bh_setup_windows_common_user`: install common user software (i.e., googlechrome, vlc, 7zip, ccleaner, FoxitReader).
2. `bh_install_battle_steam`(optional for gamers): install Battle.net and Steam

## setup Windows

1. `bh_setup_windows`: configure Windows (e.g., disable unused services/features/apps, dark mode) and install essential software (e.g., choco, gsudo, winget, git (and git bash), python, WindowsTerminal, vscode).
2. at git bash, run `bh_update_clean` (run routinely): configure/upgrade packges using variables (e.g. PKGS_PYTHON) in ~/.bashrc or ~/.bh-cfg.sh, and cleanup.

## setup WSL (after setup Windows)

1. `bh_install_wsl_ubuntu`: install WSL/Ubuntu (version 2, fixed home). This helper automate the process describred in [Microsoft WSL Tutorial](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install)  
  1.1. After run, it requeres restart windows and run it again.  
  1.2. It aso require run Ubuntu app and configure your username/password.  
  1.1. Then run it again.
2. at wsl bash, run `bh_setup_wsl`: install essential software (e.g., git, wget, curl, python).
3. at wsl bash, run `bh_update_clean` (run routinely): configure/upgrade packges using variables (e.g., PKGS_APT, PKGS_PYTHON, PKGS_REMOVE_APT) in ~/.bashrc or ~/.bh-cfg.sh, and cleanup.

## setup Windows msys2 (after setup Windows)

1. `bh_install_msys`: install msys (Cygwin-based) with bash to build GNU-based win32 applications
2. at msys bash, run `bh_setup_msys`: install essential software (e.g., wget, curl, python).
3. at msys bash, run `bh_update_clean` (run routinely): configure/upgrade packges using variables (e.g., PKGS_MSYS, PKGS_PYTHON_MSYS) in ~/.bashrc or ~/.bh-cfg.sh, and cleanup.

## Other helpers

There are other herpers related with install software, please see the [libs folder](libs/). Some examplesas are:
[bh_git_*](libs/git.sh), [bh_python_*](libs/git.sh), [bh_ffmpeg_*](libs/git.sh), [bh_diff_*](libs/git.sh), [bh_pdf_*](libs/git.sh), [bh_wget_*](libs/git.sh), [bh_curl_*](libs/git.sh), [bh_cmake_*](libs/git.sh), [bh_meson_*](libs/git.sh), [bh_code_*](libs/git.sh), [bh_compress_*](libs/compression.sh), etc.

## References

Other github projects were used as inspiration and reference:

* https://github.com/wd5gnr/bashrc
* https://github.com/martinburger/bash-common-helpers
* https://github.com/jonathantneal/git-bash-helpers
* https://github.com/Bash-it/bash-it
* https://github.com/donnemartin/dev-setup
* https://github.com/aspiers/shell-env

particulary for helpers on win:

* https://github.com/adolfintel/Windows10-Privacy
* https://gist.github.com/alirobe/7f3b34ad89a159e6daa1
* https://github.com/RanzigeButter/fyWin10/blob/master/fyWin10.ps1
* https://github.com/madbomb122/Win10Script/blob/master/Win10-Menu.ps1
* https://github.com/Sycnex/Windows10Debloater/blob/master/Windows10Debloater.ps1
* https://github.com/W4RH4WK/Debloat-Windows-10/tree/master/scripts
