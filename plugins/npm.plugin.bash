function npm_install() {
  local pkgs_to_install=""
  local pkgs_installed=$(npm ls -g --depth 0 2>/dev/null | grep -v UNMET | cut -d' ' -f2 -s | cut -d'@' -f1 | tr '\n' ' ')
  for i in "$@"; do
    if [[ ! $pkgs_installed =~ $i ]]; then
      pkgs_to_install="$i $pkgs_to_install"
    fi
  done
  if test ! -z "$pkgs_to_install"; then
    log_msg "pkgs_to_install=$pkgs_to_install"
    if test -e pakcage.json; then cd /tmp/; fi
    if test $IS_WIN; then
      npm install -g $pkgs_to_install
      npm update
    else
      sudo npm install -g $pkgs_to_install
      sudo npm update
    fi
    if test "$(pwd)" == "/tmp"; then cd - >/dev/null; fi
  fi
}
