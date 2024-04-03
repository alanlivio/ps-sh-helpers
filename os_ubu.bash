# -- essentials --

function ubu_update() {
    log_msg "apt update"
    sudo apt update
    log_msg "apt upgrade all"
    sudo apt -y upgrade
    log_msg "apt autoremove"
    sudo apt -y autoremove
}

alias apt_ppa_remove="sudo add-apt-repository --remove"
alias apt_ppa_list="apt policy"
alias apt_autoremove="sudo apt -y autoremove"

alias ps_user='ps -u $USERNAME|grep -v ps -u'

function apt_file_search() {
    : ${1?"Usage: ${FUNCNAME[0]} <file>"}
    type -p apt-file >/dev/null || sudo apt install apt-file
    apt-file search $1
}

function apt_fixes() {
    sudo dpkg --configure -a
    sudo apt install -f --fix-broken
    sudo apt-get update --fix-missing
    sudo apt -y dist-upgrade
    sudo apt -y autoremove
}

function deb_install_file_from_url() {
    : ${1?"Usage: ${FUNCNAME[0]} <debfile>"}
    local deb_name=$(basename "$1")
    if test ! -f /tmp/$deb_name; then
        curl -O "$1" --create-dirs --output-dir /tmp/
        if test $? != 0; then log_error "curl failed." && return 1; fi
    fi
    sudo dpkg -i /tmp/$deb_name
}

alias linux_product_name='sudo dmidecode -s system-product-name'
alias linux_list_gpu="lspci -nn | grep -E 'VGA|Display'"
alias linux_initd_services_list='service --status-all'

function user_sudo_no_password() {
    if ! test -d /etc/sudoers.d/; then sudo mkdir -p /etc/sudoers.d/; fi
    SET_USER=$USER && sudo sh -c "echo $SET_USER 'ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sudoers-user"
}

function ubu_disable_snap_dir_at_home() {
    sudo snap set system experimental.hidden-snap-folder=true
}

function ubu_disable_esam_hook() {
    sudo systemctl mask apt-news.service
    sudo systemctl mask esm-cache.service
    test /etc/apt/apt.conf.d/20apt-esm-hook.conf || sudo mv /etc/apt/apt.conf.d/20apt-esm-hook.conf /etc/apt/apt.conf.d/20apt-esm-hook.conf.disabled
}

function ubu_enable_git_ppa() {
    local codename=$(cat /etc/os-release | grep UBUNTU_CODENAME | cut -d = -f 2)
    if ! test -f /etc/apt/sources.list.d/git-core-ubuntu-ppa-$codename.list; then
        sudo apt-add-repository ppa:git-core/ppa --yes
    fi
}

function ubu_install_latex() {
    sudo apt install latexmk texlive-latex-extra texlive-fonts-extra
}

function ubu_install_node_npm(){
    type -p node >/dev/null || sudo snap install --classic node
    type -p npm >/dev/null || sudo npm install -g npm
}

function ubu_install_gh() {
    # https://github.com/cli/cli/blob/trunk/docs/install_linux.md
    type -p curl >/dev/null || (sudo apt update && sudo apt install curl -y)
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg &&
        sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg &&
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list >/dev/null &&
        sudo apt update &&
        sudo apt install gh -y
}

function ubu_install_miniconda() {
    # https://docs.conda.io/projects/miniconda/en/latest/
    mkdir -p ~/bin/miniconda3
    wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O ~/bin/miniconda3/miniconda.sh
    bash ~/bin/miniconda3/miniconda.sh -b -u -p ~/bin/miniconda3
    rm -rf ~/bin/miniconda3/miniconda.sh
}

function ubu_increase_swap() {
    sudo fallocate -l 1G /swapfile
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
    sudo cp /etc/fstab /etc/fstab.bak
    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
}

function gnome_dark_mode() {
    # dark mode
    gsettings set org.gnome.desktop.interface cursor-theme 'DMZ-Black'
    gsettings set org.gnome.desktop.interface gtk-theme 'Adwaita-dark'
    gsettings set org.gnome.desktop.interface icon-theme 'ubuntu-mono-dark'
    # dark desktop
    gsettings set org.gnome.desktop.background color-shading-type "solid"
    gsettings set org.gnome.desktop.background picture-uri ''
    gsettings set org.gnome.desktop.background primary-color "#000000"
    gsettings set org.gnome.desktop.background secondary-color "#000000"
}

function gnome_nautilus_list_view() {
    # recent files
    gsettings set org.gnome.desktop.privacy remember-recent-files false
    # nautilus
    gsettings set org.gnome.nautilus.list-view default-zoom-level 'small'
    gsettings set org.gnome.nautilus.list-view default-visible-columns "['name', 'size']"
    gsettings set org.gnome.nautilus.list-view use-tree-view true
    gsettings set org.gnome.nautilus.preferences default-folder-viewer 'list-view'
    gsettings set org.gnome.nautilus.window-state sidebar-width 180
}
