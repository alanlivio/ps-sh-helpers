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

function wsl_install_cuda_cudnn() {
    # https://canonical-ubuntu-wsl.readthedocs-hosted.com/en/latest/tutorials/gpu-cuda/
    sudo apt-key del 7fa2af80
    wget https://developer.download.nvidia.com/compute/cuda/repos/wsl-ubuntu/x86_64/cuda-wsl-ubuntu.pin /tmp/cuda-wsl-ubuntu.pin
    sudo mv tmp/cuda-wsl-ubuntu.pin /etc/apt/preferences.d/cuda-repository-pin-600
    sudo apt-key adv --fetch-keys https://developer.download.nvidia.com/compute/cuda/repos/wsl-ubuntu/x86_64/3bf863cc.pub
    sudo add-apt-repository -y 'deb https://developer.download.nvidia.com/compute/cuda/repos/wsl-ubuntu/x86_64/ /'
    # https://itsfoss.com/key-is-stored-in-legacy-trusted-gpg/
    sudo apt-key export 3BF863CC | sudo gpg --dearmour -o /etc/apt/trusted.gpg.d/cudatools.gpg
    sudo apt-get update
    sudo apt-get -y install cuda nvidia-cudnn
}

# -- msys2 --

if type pacman &>/dev/null; then
    alias msys2_search='pacman -s --noconfirm'
    alias msys2_show='pacman -Qi'
    alias msys2_list_installed='pacman -Qqe'
    alias msys2_install='pacman -S --noconfirm'
    alias msys2_uninstall='pacman -R --noconfirm'
    alias msys2_use_same_home='echo db_home: windows >>/etc/nsswitch.conf'
fi
