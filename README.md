<h1 align="center">bash-helpers</h1>

This project offers cross-plataform (linux, macOS, windows) bash helpers to: configure OS (e.g., disable unused services/features/apps, dark mode), install software (e.g., git, python, vscode) and utilities (e.g., install software, git, pdf, compress).

# How to install

The bash-helpers has two requeriments: a `bash shell` and `git`.  
You can install `git` in any OS following steps from [here](https://git-scm.com/download).  

Linux and macOS support bash by default.  
In Windows, the [Git Installer](https://git-scm.com/download/win) also install a bash called `git bash` (when installer, enable WindowsTerminal config and use unix like ending lines). However, `git bash` do not use your home folder by default, to fix that run in powershell:

```powershell
  [Environment]::SetEnvironmentVariable("HOME", "${env:UserProfile}")
```

Then, in `bash` (or `git bash`), you can clone and enable bash-helpers by extending your [Bash Startup File](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html). To do that, run in bash:

```bash
  git clone https://github.com/alanlivio/bash-helpers.git ~/.bh
    echo "source ~/.bh/rc.sh" >> ~/.bashrc &&\
    source ~/.bashrc
  ```

# helpers for setup

### setup Gnome-based Ubuntu  

  1. at bash, run `bh_setup_ubuntu`: configure Gnome (e.g., disable unused services/features/apps, dark mode) and install essential software (e.g., git, python, vscode).
  2. at bash, run `bh_update_clean_ubuntu` (run routinely): configure/upgrade packges using variables (PKGS_APT, PKGS_PYTHON, PKGS_SNAP, PKGS_SNAP_CLASSIC, PKGS_REMOVE_APT) in ~/.bashrc or ~/.bh-cfg.sh, and cleanup.

### setup macOS  

  1. at bash, run `bh_setup_mac`: install essential software (brew, bash last version, python, vscode)
  2. at bash, run `bh_update_clean_mac` (run routinely): configure/upgrade packges using variables (PKGS_BREW) in ~/.bashrc or ~/.bh-cfg.sh, and cleanup.

### setup Windows

  1. at git bash, run `bh_setup_win`: configure Windows (e.g., disable unused services/features/apps, dark mode) and install essential software (e.g., choco, gsudo, winget, python, WindowsTerminal, vscode).
  2. `bh_update_clean_win` (run routinely): configure/upgrade packges using variables (e.g. PKGS_PYTHON) in ~/.bashrc or ~/.bh-cfg.sh, and cleanup.

### setup WSL (after setup Windows)

  1. at git bash, run `bh_win_install_wsl_ubuntu`: install WSL/Ubuntu (version 2, fixed home). This helper automate the process describred in [Microsoft WSL Tutorial](https://docs.microsoft.com/en-us/windows/wsl/wsl2-install)  
    1.1. After run, it requeres restart windows and run it again.  
    1.2. It aso require run Ubuntu app and configure your username/password.  
    1.1. Then run it again.

  2. at wsl bash, run `bh_setup_wsl`: install essential software (e.g., git, python).
  3. at wsl bash, run `bh_update_clean_wsl` (run routinely): configure/upgrade packges using variables (e.g., PKGS_APT, PKGS_PYTHON, PKGS_REMOVE_APT) in ~/.bashrc or ~/.bh-cfg.sh, and cleanup.

### setup Windows msys2 (after setup Windows)

  1. at git bash, run `bh_win_install_msys`: install msys (Cygwin-based) with bash to build GNU-based win32 applications
  2. at msys bash, run `bh_setup_msys`: install essential software (e.g., python).
  3. at msys bash, run `bh_update_clean_msys` (run routinely): configure/upgrade packges using variables (e.g., PKGS_MSYS, PKGS_PYTHON_MSYS) in ~/.bashrc or ~/.bh-cfg.sh, and cleanup.
  

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
