<h1 align="center">bash-helpers</h1>

This project offers bash helpers to: configure OS (e.g., disable unused services/features/apps, dark mode), install software (e.g., git, python, vscode) and utilities (e.g., install software, git, pdf, compression).

# How to install

To enable helpers in bash (Ubuntu, macOS, or WSL), the bash-helpers can be used as a [Bash Startup File](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html). To do that, run the followings commands for fetch rc.sh and load at `~/.bashrc` :

```bash
  mkdir -p ~/.bh/ &&\
    wget -O ~/.bh/rc.sh https://raw.githubusercontent.com/alanlivio/bash-helpers/master/rc.sh &&\
    echo "source ~/.bh/rc.sh" >> ~/.bashrc &&\
    source ~/.bashrc
  ```

To enable in powershell (Windows), the bash-helpers can be used as a [PowerShell Profile](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles?view=powershell-7). To do that, run the followings commands for fetch rc.ps1 and import it as powershell module:

```powershell
  mkdir -p ~/.bh/ -ea 0;`
    Invoke-WebRequest -O ~/.bh/rc.ps1 https://raw.githubusercontent.com/alanlivio/bash-helpers/master/rc.ps1;`
    Set-ExecutionPolicy unrestricted -force;`
    Write-Output "Import-Module -Force -Global ~/.bh/rc.ps1" > $Profile.AllUsersAllHosts;`
    powershell -nologo
  ```

# Usage

## setup Gnome-based Ubuntu

1. at bash, run `bh_setup_ubuntu`: configure Gnome (e.g., disable unused services/features/apps, dark mode) and install essential software (e.g., git, wget, curl, python, vscode).
2. at bash, run `bh_update_clean` (run routinely): configure/upgrade packges using variables (PKGS_APT, PKGS_PYTHON, PKGS_SNAP, PKGS_SNAP_CLASSIC, PKGS_REMOVE_APT) in ~/.bashrc or ~/.bh-cfg.sh, and cleanup.

## setup macOS

1. at bash, run `bh_setup_mac`: install essential software (brew, bash last version, python, vscode)
2. at bash, run `bh_update_clean` (run routinely): configure/upgrade packges using variables (PKGS_BREW) in ~/.bashrc or ~/.bh-cfg.sh, and cleanup.

## setup Windows for common (non-dev) users

1. at powershell, run `bh_setup_windows_common_user`: install common user software (i.e., googlechrome, vlc, 7zip, ccleaner, FoxitReader).
2. at powershell, run `bh_install_battle_steam`(optional for gamers): install Battle.net and Steam

## setup Windows with git_bash

1. at powershell, run `bh_setup_windows`: configure Windows (e.g., disable unused services/features/apps, dark mode) and install essential software (e.g., choco, gsudo, winget, git (and git bash), python, WindowsTerminal, vscode).
2. at git bash, run `bh_update_clean` (run routinely): configure/upgrade packges using variables (e.g. PKGS_PYTHON) in ~/.bashrc or ~/.bh-cfg.sh, and cleanup.

## setup WSL (after setup Windows)

1. at powershell, run `bh_install_wsl_ubuntu`: install WSL/Ubuntu (version 2, fixed home). This helper automate the process describred in [Microsoft WSL Tutorial](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install)  
  1.1. After run, it requeres restart windows and run it again.  
  1.2. It aso require run Ubuntu app and configure your username/password.  
  1.1. Then run it again.
2. at wsl bash, run `bh_setup_wsl`: install essential software (e.g., git, wget, curl, python).
3. at wsl bash, run `bh_update_clean` (run routinely): configure/upgrade packges using variables (e.g., PKGS_APT, PKGS_PYTHON, PKGS_REMOVE_APT) in ~/.bashrc or ~/.bh-cfg.sh, and cleanup.

## setup msys2 (after setup Windows)

1. at powershell, run `bh_install_msys`: install msys (Cygwin-based) with bash to build GNU-based win32 applications
2. at msys bash, run `bh_setup_msys`: install essential software (e.g., wget, curl, python).
3. at msys bash, run `bh_update_clean` (run routinely): configure/upgrade packges using variables (e.g., PKGS_MSYS, PKGS_PYTHON_MSYS) in ~/.bashrc or ~/.bh-cfg.sh, and cleanup.

## Other helpers

There are other herpers related with install software ( `bh_install_` \*), git ( `bh_git_` \*), pdf manipulation ( `bh_pdf_` \*), files compression ( `bh_compress_` \*), etc. To see them, take a look at [rc.ps1](rc.ps1) and [rc.sh](rc.sh).

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
