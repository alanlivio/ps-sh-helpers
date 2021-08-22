<h1 align="center">bash-helpers</h1>

This project offers cross-plataform (linux, macOS, windows) bash helpers to: configure OS (e.g., dark mode, sanity desktop inteface ), install software (e.g., git, python, vscode) and utilities (e.g., install software, git, pdf, compress).

# How to install

The bash-helpers has two requeriments: a `bash shell` and `git` . To fast way to install them are run:

in mac use [install/bh-for-mac.sh](install/bh-for-mac.sh):

```bash
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/alanlivio/bash-helpers/master/install/bh-for-mac.sh)"
```

in ubuntu [install/bh-for-ubuntu.sh](install/bh-for-ubuntu.sh):

```bash
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/alanlivio/bash-helpers/master/install/bh-for-ubuntu.sh)"
```

in windows [install/bh-for-win.sh](install/bh-for-win.sh):

```powershell
  Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/alanlivio/bash-helpers/master/install/bh-for-win.sh'))
```

# helpers for setup

### setup Gnome-based Ubuntu  

  1. at bash, run `bh_setup_ubuntu`: configure Gnome (e.g., dark mode, sanity desktop inteface ) and install essential software (e.g., python, vscode).
  2. at bash, run `bh_update_clean_ubuntu` (run routinely): configure/upgrade packges using variables (BH_PKGS_APT_UBUNTU, BH_PKGS_PYTHON, BH_PKGS_SNAP, BH_PKGS_SNAP_CLASSIC, BH_PKGS_APT_REMOVE_UBUNTU) in ~/.bashrc or ~/.bh-cfg.sh, and cleanup.

### setup macOS  

  1. at bash, run `bh_setup_mac`: install essential software (bash last version, python, vscode)
  2. at bash, run `bh_update_clean_mac` (run routinely): configure/upgrade packges using variables (BH_PKGS_BREW) in ~/.bashrc or ~/.bh-cfg.sh, and cleanup.

### setup Windows

  1. at git bash, run `bh_setup_win`: configure Windows (e.g., dark mode, sanity desktop inteface ) and install essential software (e.g., python, vscode).
  2. at git bash, run `bh_update_clean_win` (run routinely): configure/upgrade packges using variables (e.g. BH_PKGS_PYTHON) in ~/.bashrc or ~/.bh-cfg.sh, and cleanup.

### setup WSL

  1. at git bash, run `bh_setup_wsl`: install WSL/Ubuntu (version 2, fixed home). This helper automate the process describred in [Microsoft WSL Tutorial](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install). After run, it requeres restart windows and run it again. When Ubuntu app started, you need configure your username/password.  
  2. at wsl bash, run `bh_update_clean_wsl` (run routinely): configure/upgrade packges using variables (e.g., BH_PKGS_APT_WSL, BH_PKGS_PYTHON_WSL, BH_PKGS_APT_REMOVE_WSL) in ~/.bashrc or ~/.bh-cfg.sh, and cleanup.

### setup Windows msys2

  1. at git bash, run `bh_setup_msys`: install msys (Cygwin-based) with bash to build GNU-based win32 applications
  2. at msys bash, run `bh_update_clean_msys` (run routinely): configure/upgrade packges using variables (e.g., BH_PKGS_MSYS, BH_PKGS_PYTHON_MSYS) in ~/.bashrc or ~/.bh-cfg.sh, and cleanup.
  

# helpers for commands
* android helpers: see `bh_android_*` at [lib/android.sh](lib/android.sh).
* cmake helpers: see `bh_cmake_*` at [lib/cmake.sh](lib/cmake.sh).
* compress helpers: see `bh_compress_*` at [lib/compress.sh](lib/compress.sh), etc.
* curl helpers: see `bh_curl_*` at [lib/curl.sh](lib/curl.sh).
* diff helpers: see `bh_diff_*` at [lib/diff.sh](lib/diff.sh).
* docker helpers: see `bh_docker_*` at [lib/docker.sh](lib/docker.sh).
* ffmpeg helpers: see `bh_ffmpeg_*` at [lib/ffmpeg.sh](lib/ffmpeg.sh).
* ffmpeg helpers: see `bh_find_*` at [lib/find.sh](lib/find.sh).
* git helpers: see `bh_git_*` at [lib/git.sh](lib/git.sh).
* git helpers: see `bh_gcc_*` at [lib/gcc.sh](lib/gcc.sh).
* meson helpers: see `bh_meson_*` at [lib/meson.sh](lib/meson.sh).
* mount helpers: see `bh_mount_*` at [lib/mount.sh](lib/mount.sh).
* mount helpers: see `bh_npm_*` at [lib/npm.sh](lib/mount.sh).
* pandoc helpers: see `bh_pandoc_*` at [lib/pandoc.sh](lib/pandoc.sh).
* pdf helpers: see `bh_pdf_*` at [lib/pdf.sh](lib/pdf.sh).
* python helpers: see `bh_python_*` at [lib/python.sh](lib/python.sh).
* vscode helpers: see `bh_vscode_*` at [lib/vscode.sh](lib/vscode.sh).
* wget helpers: see `bh_wget_*` at [lib/wget.sh](lib/wget.sh).
* wget helpers: see `bh_youtubedl_*` at [lib/youtubedl.sh](lib/youtubedl.sh).
* other helpers: There are other herpers related with install software, please see the [libs folder](lib/).

## References

Other github projects were used as reference:

* https://github.com/wd5gnr/bashrc
* https://github.com/martinburger/bash-common-helpers
* https://github.com/jonathantneal/git-bash-helpers
* https://github.com/Bash-it/bash-it
* https://github.com/donnemartin/dev-setup
* https://github.com/aspiers/shell-env

And, particulary, references for helpers on Windows:

* https://github.com/adolfintel/Windows10-Privacy
* https://gist.github.com/alirobe/7f3b34ad89a159e6daa1
* https://github.com/RanzigeButter/fyWin10/blob/master/fyWin10.ps1
* https://github.com/madbomb122/Win10Script/blob/master/Win10-Menu.ps1
* https://github.com/Sycnex/Windows10Debloater/blob/master/Windows10Debloater.ps1
* https://github.com/W4RH4WK/Debloat-Windows-10/tree/master/scripts
