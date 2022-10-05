alias python_install='pip install '
alias python_uninstall='pip uninstall  '

function python_upgrade_outdated() {
  local outdated=$(pip list --outdated --format=freeze --disable-pip-version-check 2>/dev/null | grep -v '^\-e' | cut -d = -f 1)
  if test "$outdated"; then
    python -m pip install --upgrade pip 2>/dev/null
    pip install --upgrade $outdated 2>/dev/null
  fi
}

function venv_create() {
  deactivate
  if test -d ./venv/bin/; then rm -r ./venv; fi
  python -m venv venv
  if test requirements.txt; then pip install -r requirements.txt; fi
}

function venv_activate_install() {
  deactivate
  source venv/bin/activate
  if test requirements.txt; then pip install -r requirements.txt; fi
}

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
