# -- essentials --

alias start_from_wsl='wslview'

if [[ -n $WSL_DISTRO_NAME ]]; then
    alias winpath='wslpath -m'
else
    alias winpath='cygpath -m'
fi

# -- load funcs from os_win.ps1 as aliases --

function _ps_call() {
    powershell.exe -command "& { . $(wslpath -w $BH_DIR/os_win.ps1); $* }"
}

function _ps_def_func() {
    eval "function $1() { _ps_call $*; }"
}

_regex_no_underscore_func='function\s([^_][^{]+)\('
while read -r line; do
    if [[ $line =~ $_regex_no_underscore_func ]]; then
        func=${BASH_REMATCH[1]}
        _ps_def_func $func
    fi
done <$BH_DIR/os_win.ps1

# -- msys2 --

if type pacman &>/dev/null; then
    alias msys2_search='pacman -s --noconfirm'
    alias msys2_show='pacman -Qi'
    alias msys2_list_installed='pacman -Qqe'
    alias msys2_install='pacman -S --noconfirm'
    alias msys2_uninstall='pacman -R --noconfirm'
    alias msys2_use_same_home='echo db_home: windows >>/etc/nsswitch.conf'
fi
