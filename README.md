# ps-sh-helpers

`ps-sh-helpers` is a template for creating your library PowerShell and Bash helpers.  It is very usfeull for Windows users that wants take the best of WSL Bash and integrate it with PowerShell.

`ps-sh-helpers`  organize helpers in OS-dependent from `os/<os>.*` files and loads program-dependent from `programs/<program>.*` files. It is initialized at `.bashrc` by loading `init.sh` or at `PowerShell_profile.ps1` by loading `init.ps1` (see diagram below).

```mermaid
%%{init: {'theme':'dark'}}%%
flowchart LR
    bashrc[".bashrc"]
    ps-init["init.ps1"]
    sh-init["init.sh"]
    program-dependent["
        programs/[program].bash
        ...
    "]
    OS-dependent["
        os/win.bash
        os/ubu.bash
        ...
    "]
    
    bashrc --> |"loads"| sh-init
    sh-init --> |"loads if program exists"| program-dependent
    sh-init --> |"loads if runing at OS"| OS-dependent
    sh-init --> |"bash alias to each function at"| ps-init
```

```mermaid
%%{init: {'theme':'dark'}}%%
flowchart LR
    psprofile["Microsoft.PowerShell_profile.ps1"]
    ps-init["init.ps1"]
    sh-init["init.sh"]
    program-dependent["
        programs/[program].ps1
        ...
    "]
    OS-dependent["
        os/win.ps1
        os/ubu.ps1
        ...
    "]

    psprofile--> |"loads"| ps-init
    ps-init --> |"loads if program exists"| program-dependent
    ps-init --> |"loads if runing at OS"| OS-dependent
    ps-init --> |"bash alias to each function at"| sh-init
```

## How to install

At Bash, you call install `ps-sh-helpers` by:

```bash
git clone https://github.com/alanlivio/ps-sh-helpers ~/.ps1-sh-helpers
echo "source ~/.ps-sh-helpers/init.sh" >> ~/.bashrc
```

At PowerShell, you can install `ps-sh-helpers` by:

```ps1
git clone https://github.com/alanlivio/ps-sh-helpers ${env:userprofile}\.ps1-sh-helpers
$contentAdd = '. "${env:userprofile}\.ps-sh-helpers\init.ps1""'
Set-Content "${env:userprofile}/OneDrive/Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1" $contentAdd
```

## References

This project takes inspiration from:

- <https://github.com/Bash-it/bash-it>
- <https://github.com/milianw/shell-helpers>
- <https://github.com/wd5gnr/bashrc>
- <https://github.com/martinburger/bash-common-helpers>
- <https://github.com/jonathantneal/git-bash-helpers>
- <https://github.com/donnemartin/dev-setup>
- <https://github.com/aspiers/shell-env>
- <https://github.com/nafigator/bash-helpers>
- <https://github.com/TiSiE/BASH.helpers>
- <https://github.com/midwire/bash.env>
- <https://github.com/e-picas/bash-library>
- <https://github.com/awesome-windows11/windows11>
- <https://github.com/99natmar99/Windows-11-Fixer>
- <https://github.com/W4RH4WK/Debloat-windows-10/tree/master/scripts>
