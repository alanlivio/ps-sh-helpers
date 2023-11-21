# -- essentials --

function ubu_update() {
    log_msg "apt update"
    sudo apt -y update
    if test -n "$BH_PKGS_APT"; then
        log_msg "apt install pkgs from var BH_PKGS_APT: $BH_PKGS_APT"
        sudo apt install -y $BH_PKGS_APT
    fi
    log_msg "apt upgrade all"
    sudo apt -y upgrade
    log_msg "apt autoremove"
    sudo apt -y autoremove
}

# -- apt --

alias apt_ppa_remove="sudo add-apt-repository --remove"
alias apt_ppa_list="apt policy"
alias apt_autoremove="sudo apt -y autoremove"

function apt_fixes() {
    sudo dpkg --configure -a
    sudo apt install -f --fix-broken
    sudo apt-get update --fix-missing
    sudo apt dist-upgrade
    sudo apt autoremove -y
}
alias apt_list_avaliable_java="aptitude search '?provides(java-runtime)'"

# -- deb --

alias deb_info_file='dpkg-deb --info'
alias deb_contents_file='dpkg-deb --show'
alias deb_install_file='sudo dpkg -i'
alias deb_install_file_force_depends='sudo dpkg -i --force-depends'

function deb_install_file_from_url() {
    : ${1?"Usage: ${FUNCNAME[0]} <debfile>"}
    local deb_name=$(basename "$1")
    if test ! -f /tmp/$deb_name; then
        curl -O "$1" --create-dirs --output-dir /tmp/
        if test $? != 0; then log_error "curl failed." && return 1; fi
    fi
    sudo dpkg -i /tmp/$deb_name
}

# -- system --

alias linux_product_name='sudo dmidecode -s system-product-name'
alias linux_list_gpu="lspci -nn | grep -E 'VGA|Display'"
alias linux_initd_services_list='service --status-all'

function user_sudo_nopasswd() {
    if ! test -d /etc/sudoers.d/; then test_and_create_dir /etc/sudoers.d/; fi
    SET_USER=$USER && sudo sh -c "echo $SET_USER 'ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/sudoers-user"
}

function ubu_install_wsl_cuda_11() {
    # https://ubuntu.com/tutorials/enabling-gpu-acceleration-on-ubuntu-on-wsl2-with-the-nvidia-cuda-platform#3-install-nvidia-cuda-on-ubuntu
    # how fix gpg key: https://developer.nvidia.com/blog/updating-the-cuda-linux-gpg-repository-key/
    sudo apt-key del 7fa2af80
    wget https://developer.download.nvidia.com/compute/cuda/repos/wsl-ubuntu/x86_64/cuda-keyring_1.0-1_all.deb
    sudo dpkg -i cuda-keyring_1.0-1_all.deb
    sudo apt-get update
    sudo apt-get -y install cuda-11-8
}

function gnome_sanity() {
    # dark mode
    gsettings set org.gnome.desktop.interface cursor-theme 'DMZ-Black'
    gsettings set org.gnome.desktop.interface gtk-theme 'Adwaita-dark'
    gsettings set org.gnome.desktop.interface icon-theme 'ubuntu-mono-dark'
    # dark desktop
    gsettings set org.gnome.desktop.background color-shading-type "solid"
    gsettings set org.gnome.desktop.background picture-uri ''
    gsettings set org.gnome.desktop.background primary-color "#000000"
    gsettings set org.gnome.desktop.background secondary-color "#000000"
    # clock
    gsettings set org.gnome.desktop.interface clock-show-date true
    # notifications
    gsettings set org.gnome.desktop.notifications show-banners false
    gsettings set org.gnome.desktop.notifications show-in-lock-screen false
    # recent files
    gsettings set org.gnome.desktop.privacy remember-recent-files false
    # sound
    gsettings set org.gnome.desktop.sound event-sounds false
    gsettings set org.gnome.desktop.wm.preferences num-workspaces 1
    # nautilus
    gsettings set org.gnome.nautilus.list-view default-zoom-level 'small'
    gsettings set org.gnome.nautilus.list-view default-visible-columns "['name', 'size']"
    gsettings set org.gnome.nautilus.list-view use-tree-view true
    gsettings set org.gnome.nautilus.preferences default-folder-viewer 'list-view'
    gsettings set org.gnome.nautilus.window-state maximized false
    gsettings set org.gnome.nautilus.window-state sidebar-width 180
}
