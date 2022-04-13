# ---------------------------------------
# py
# ---------------------------------------

function py_clean() {
  find . -name .ipynb_checkpoints -o -name __pycache__ | xargs -r rm -r
}

function py_version() {
  python -V 2>&1 | grep -Po '(?<=Python ).{1}'
}

function py_list_installed() {
  pip list
}

function py_upgrade() {
  log_func
  local outdated=$(pip list --outdated --format=freeze --disable-pip-version-check 2>/dev/null | grep -v '^\-e' | cut -d = -f 1)
  if test "$outdated"; then
    pip install --upgrade pip 2>/dev/null
    pip install --upgrade $outdated 2>/dev/null
  fi
}

function py_install() {
  log_func

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

function py_uninstall() {
  pip uninstall "$@"
}

function py_set_v3_default() {
  if [[ $(type python) && $(python -V) != "Python 3"* ]]; then
    sudo update-alternatives --install /usr/bin/python python /usr/bin/python3 1
    sudo update-alternatives --install /usr/bin/pip pip /usr/bin/pip3 1
  fi
}

function py_venv_create() {
  deactivate
  if test -d ./venv/bin/; then rm -r ./venv; fi
  python -m venv venv
  if test requirements.txt; then pip install -r requirements.txt; fi
}

function py_venv_load() {
  deactivate
  source venv/bin/activate
  if test requirements.txt; then pip install -r requirements.txt; fi
}

function py_http_host_dir() {
  python -m http.server 80
}

# ---------------------------------------
# setup
# ---------------------------------------

function py_setup_user_install() {
  python setup.py install --user
}

function py_setup_upload_testpypi() {
  rm -r dist/
  python setup.py sdist bdist_wheel
  twine check dist/*
  twine upload --repository testpypi dist/* -u $PYPI_USER -p "$PYPI_PASS"
}

function py_setup_upload() {
  rm -r dist/
  python setup.py sdist bdist_wheel
  twine check dist/*
  twine upload dist/* -u $PYPI_USER -p "$PYPI_PASS"
}

# ---------------------------------------
# jupyter
# ---------------------------------------

if type jupyter &>/dev/null; then
  function py_jupyter_notebook() {
    jupyter notebook
  }

  function py_jupyter_remove_output() {
    jupyter nbconvert --ClearOutputPreprocessor.enabled=True --inplace $@
  }
fi

# ---------------------------------------
# pygmentize
# ---------------------------------------

if type pygmentize &>/dev/null; then
  function py_pygmentize_dir_xml_files_by_extensions_to_jpeg() {
    : ${1?"Usage: ${FUNCNAME[0]} <dir>"}
    find . -maxdepth 1 -name "*.xml" | while read -r i; do
      pygmentize -f jpeg -l xml -o $i.jpg $i
    done
  }
  function py_pygmentize_dir_xml_files_by_extensions_to_rtf() {
    : ${1?"Usage: ${FUNCNAME[0]} <dir>"}

    find . -maxdepth 1 -name "*.xml" | while read -r i; do
      pygmentize -f jpeg -l xml -o $i.jpg $i
      pygmentize -P fontsize=16 -P fontface=consolas -l xml -o $i.rtf $i
    done
  }
  function py_pygmentize_dir_xml_files_by_extensions_to_html() {
    : ${1?"Usage: ${FUNCNAME[0]} ARGUMENT"}
    find . -maxdepth 1 -name "*.xml" | while read -r i; do
      pygmentize -O full,style=default -f html -l xml -o $i.html $i
    done
  }
fi
