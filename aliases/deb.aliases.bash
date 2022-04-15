alias deb_install='sudo dpkg -i'
alias deb_install_force_depends='sudo dpkg -i --force-depends'
alias deb_info='dpkg-deb --info'
alias deb_contents='dpkg-deb --show'
function deb_fetch_install() {
  local deb_name=$(basename $1)
  if test ! -f /tmp/$deb_name; then
    decompress_from_url $1 /tmp/
    if test $? != 0; then log_error "decompress_from_url failed." && return 1; fi
  fi
  sudo dpkg -i /tmp/$deb_name
}
