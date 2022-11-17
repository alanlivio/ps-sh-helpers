# ########################
# apt
# ########################

alias apt_upgrade="sudo apt -y update; sudo apt -y upgrade"
alias apt_update="sudo apt -y update"
alias apt_ppa_remove="sudo add-apt-repository --remove"
alias apt_ppa_list="apt policy"
alias apt_install="sudo apt install -y"
alias apt_autoremove="sudo apt -y autoremove"
alias apt_clean=apt_autoremove
alias apt_uninstall="sudo apt remove -y --purge "

function apt_fixes() {
  sudo dpkg --configure -a
  sudo apt install -f --fix-broken
  sudo apt-get update --fix-missing
  sudo apt dist-upgrade
}

alias deb_install='sudo dpkg -i'
alias deb_install_force_depends='sudo dpkg -i --force-depends'
alias deb_info='dpkg-deb --info'
alias deb_contents='dpkg-deb --show'

function deb_install_url() {
  local deb_name=$(basename $1)
  if test ! -f /tmp/$deb_name; then
    curl -O $1 --create-dirs --output-dir /tmp/
    if test $? != 0; then log_error "curl failed." && return 1; fi
  fi
  sudo dpkg -i /tmp/$deb_name
}

# ########################
# snap
# ########################

alias snap_install="snap install "
alias snap_install_classic="snap install --classic"
alias snap_install_edge="snap install --edge"
alias snap_list="snap list"

# ########################
# gnome settings
# ########################

if type gsettings &>/dev/null; then

  function gnome_sanity() {
    gnome_dark
    gnome_sanity
  }

  function gnome_dark_mode() {
    gsettings set org.gnome.desktop.interface cursor-theme 'DMZ-Black'
    gsettings set org.gnome.desktop.interface gtk-theme 'Adwaita-dark'
    gsettings set org.gnome.desktop.interface icon-theme 'ubuntu-mono-dark'
  }

  function gnome_sanity() {
    # dark desktop
    gsettings set org.gnome.desktop.background color-shading-type "solid"
    gsettings set org.gnome.desktop.background picture-uri ''
    gsettings set org.gnome.desktop.background primary-color "#000000"
    gsettings set org.gnome.desktop.background secondary-color "#000000"
    # gnome search
    gsettings set org.gnome.desktop.search-providers sort-order "[]"
    gsettings set org.gnome.desktop.search-providers disable-external false
    gsettings set org.gnome.desktop.search-providers disabled "['org.gnome.Calculator.desktop', 'org.gnome.Calendar.desktop', 'org.gnome.clocks.desktop', 'org.gnome.Nautilus.desktop', 'org.gnome.Terminal.desktop', 'org.gnome.Software.desktop']"
    # animation
    gsettings set org.gnome.desktop.interface enable-animations false
    # desktop
    gsettings set org.gnome.desktop.background show-desktop-icons false
    # cloack
    gsettings set org.gnome.desktop.interface clock-show-date true
    # notifications
    gsettings set org.gnome.desktop.notifications show-banners false
    gsettings set org.gnome.desktop.notifications show-in-lock-screen false
    # recent files
    gsettings set org.gnome.desktop.privacy remember-recent-files false
    # screensaver
    gsettings set org.gnome.desktop.screensaver color-shading-type "solid"
    gsettings set org.gnome.desktop.screensaver lock-enabled false
    gsettings set org.gnome.desktop.screensaver picture-uri ''
    gsettings set org.gnome.desktop.screensaver primary-color "#000000"
    gsettings set org.gnome.desktop.screensaver secondary-color "#000000"
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
    # gedit
    if grep -q gedit <<<$(gsettings list-schemas); then
      gsettings set org.gnome.gedit.preferences.editor bracket-matching true
      gsettings set org.gnome.gedit.preferences.editor display-line-numbers true
      gsettings set org.gnome.gedit.preferences.editor display-right-margin true
      gsettings set org.gnome.gedit.preferences.editor scheme 'classic'
      gsettings set org.gnome.gedit.preferences.editor wrap-last-split-mode 'word'
      gsettings set org.gnome.gedit.preferences.editor wrap-mode 'word'
    fi
    # dock
    if grep -q dash-to-dock <<<$(gsettings list-schemas); then
      gsettings set org.gnome.shell.extensions.dash-to-dock dash-max-icon-size 24
      gsettings set org.gnome.shell.extensions.dash-to-dock dock-position 'BOTTOM'
      gsettings set org.gnome.shell.extensions.dash-to-dock autohide false
      gsettings set org.gnome.shell.extensions.dash-to-dock intellihide false
      gsettings set org.gnome.shell.extensions.dash-to-dock show-show-apps-button false
    fi
  }
fi
