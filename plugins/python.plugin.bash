function python_upgrade() {
  local outdated=$(pip list --outdated --format=freeze --disable-pip-version-check 2>/dev/null | grep -v '^\-e' | cut -d = -f 1)
  if test "$outdated"; then
    pip install --upgrade pip 2>/dev/null
    pip install --upgrade $outdated 2>/dev/null
  fi
}

function python_install() {
  local pkgs_to_install=""
  local pkgs_installed=$(pip list --format=columns --disable-pip-version-check | cut -d' ' -f1 | grep -v Package | sed '1d' | tr '\n' ' ')
  for i in "$@"; do
    if [[ ! $pkgs_installed =~ $i ]]; then
      pkgs_to_install="$i $pkgs_to_install"
    fi
  done
  if test ! -z "$pkgs_to_install"; then
    log_msg "pkgs_to_install=$pkgs_to_install"
    pip install --user --no-cache-dir --disable-pip-version-check $pkgs_to_install
  fi
}

function python_uninstall() {
  pip uninstall "$@"
}

function python_venv_create() {
  deactivate
  if test -d ./venv/bin/; then rm -r ./venv; fi
  python -m venv venv
  if test requirements.txt; then pip install -r requirements.txt; fi
}

function python_venv_load() {
  deactivate
  source venv/bin/activate
  if test requirements.txt; then pip install -r requirements.txt; fi
}

# ---------------------------------------
# setup
# ---------------------------------------

function python_setup_install_user() {
  python setup.py install --user
}

function python_setup_upload_testpypi() {
  rm -r dist/
  python setup.py sdist bdist_wheel
  twine check dist/*
  twine upload --repository testpypi dist/* -u $PYPI_USER -p "$PYPI_PASS"
}

function python_setup_upload_pip() {
  rm -r dist/
  python setup.py sdist bdist_wheel
  twine check dist/*
  twine upload dist/* -u $PYPI_USER -p "$PYPI_PASS"
}
