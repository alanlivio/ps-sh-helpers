alias python_clean_cache='find . | grep -E "(/__pycache__$|\.pyc$|\.pyo$)" | xargs rm -rf'

function pip_install() {
  for i in "$@"; do
    pip show $i >/dev/null || pip install $i
  done
}


function pip_upgrade_outdated() {
  local outdated=$(pip list --outdated --format=freeze --disable-pip-version-check 2>/dev/null | grep -v '^\-e' | cut -d = -f 1)
  if test "$outdated"; then
    pip install --upgrade pip 2>/dev/null
    pip install --upgrade $outdated 2>/dev/null
  fi
}

function python_setup_install() {
  python setup.py install
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
