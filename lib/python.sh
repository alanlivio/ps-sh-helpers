function bh_python_clean() {
  find . -name .ipynb_checkpoints -o -name __pycache__ | xargs -r rm -r
}

function bh_python_version() {
  python -V 2>&1 | grep -Po '(?<=Python ).{1}'
}

function bh_python_list_installed() {
  pip list
}

function bh_python_upgrade() {
  bh_log_func
  if $IS_WINDOWS_GITBASH; then
    # in gitbash, fix  "WARNING: Ignoring invalid distribution"
    if test -d '/c/Python39/Lib/site-packages/~*'; then sudo rm -r /c/Python39/Lib/site-packages/~*; fi
  fi
  local outdated=$(pip list --outdated --format=freeze 2>/dev/null | grep -v '^\-e' | cut -d = -f 1)
  if test "$outdated"; then
    sudo pip install --upgrade pip 2>/dev/null
    sudo pip install --upgrade $outdated 2>/dev/null
  fi
}

function bh_python_install() {
  bh_log_func

  local pkgs_to_install=""
  local pkgs_installed=$(pip list --format=columns | cut -d' ' -f1 | grep -v Package | sed '1d' | tr '\n' ' ')
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
    sudo pip install --no-cache-dir --disable-pip-version-check $pkgs_to_install
  fi
  sudo pip install -U "$@" &>/dev/null
}

if $IS_LINUX; then
  function bh_python_set_python3_default() {
    sudo update-alternatives --install /usr/bin/python python /usr/bin/python3 1
    sudo update-alternatives --install /usr/bin/pip pip /usr/bin/pip3 1
  }
fi

function bh_python_venv_create() {
  deactivate
  if test -d ./venv/bin/; then rm -r ./venv; fi
  python3 -m venv venv
  if test requirements.txt; then pip install -r requirements.txt; fi
}

function bh_python_venv_load() {
  deactivate
  source venv/bin/activate
  if test requirements.txt; then pip install -r requirements.txt; fi
}

function bh_folder_host_http() {
  sudo python3 -m http.server 80
}
