function bh_npm_install() {
  bh_log_func

  local pkgs_to_install=""
  local pkgs_installed=$(npm ls -g --depth 0 2>/dev/null | grep -v UNMET | cut -d' ' -f2 -s | cut -d'@' -f1 | tr '\n' ' ')
  local found
  for i in "$@"; do
    found=false
    for j in $pkgs_installed; do
      if test $i == $j; then
        found=true
        break
      fi
    done
    if ! $found; then pkgs_to_install="$pkgs_to_install $i"; fi
  done
  if test ! -z "$pkgs_to_install"; then
    echo "pkgs_to_install=$pkgs_to_install"
    if test -f pakcage.json; then cd /tmp/; fi
    if test $IS_WINDOWS; then
      npm install -g $pkgs_to_install
      npm update
    else
      sudo npm install -g $pkgs_to_install
      sudo npm update
    fi
    if test "$(pwd)" == "/tmp"; then cd - >/dev/null; fi
  fi
}
