alias deb_install='sudo dpkg -i'
alias deb_install_force_depends='sudo dpkg -i --force-depends'
alias deb_info='dpkg-deb --info'
alias deb_contents='dpkg-deb --show'
function deb_fetch_install() {
  local deb_name=$(basename $1)
  if test ! -f /tmp/$deb_name; then
    curl -O $1 --create-dirs --output-dir /tmp/
    if test $? != 0; then log_error "curl failed." && return 1; fi
  fi
  sudo dpkg -i /tmp/$deb_name
}
