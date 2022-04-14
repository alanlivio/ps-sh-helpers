# ---------------------------------------
# ruby
# ---------------------------------------

function ruby_install() {
  local pkgs_to_install=""
  local pkgs_installed=$(gem list | cut -d' ' -f1 -s | tr '\n' ' ')
  for i in "$@"; do
    if [[ ! $pkgs_installed =~ $i ]]; then
      pkgs_to_install="$i $pkgs_to_install"
    fi
  done
  if test ! -z "$pkgs_to_install"; then
    log_msg "pkgs_to_install=$pkgs_to_install"
    gem install $pkgs_to_install
    if test "$(pwd)" == "/tmp"; then cd - >/dev/null; fi
  fi
}
