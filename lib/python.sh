# ---------------------------------------
# python
# ---------------------------------------

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
  local outdated=$(pip list --outdated --format=freeze 2>/dev/null | grep -v '^\-e' | cut -d = -f 1)
  if test "$outdated"; then
    pip install --upgrade pip 2>/dev/null
    pip install --upgrade $outdated 2>/dev/null
  fi
}

function bh_python_install() {
  bh_log_func

  local pkgs_to_install=""
  local pkgs_installed=$(pip list --format=columns | cut -d' ' -f1 | grep -v Package | sed '1d' | tr '\n' ' ')
  for i in "$@"; do
    if [[ ! $pkgs_installed =~ $i ]]; then
      pkgs_to_install="$i $pkgs_to_install"
    fi
  done
  if test ! -z "$pkgs_to_install"; then
    bh_log_msg "pkgs_to_install=$pkgs_to_install"
    pip install --user --no-cache-dir --disable-pip-version-check $pkgs_to_install
  fi
}

if $IS_LINUX; then
  function bh_python_set_python3_default() {
    if [[ $(ptyhon -V) == "Python 3" ]]; then
      bh_log_func
      update-alternatives --install /usr/bin/python python /usr/bin/python3 1
      update-alternatives --install /usr/bin/pip pip /usr/bin/pip3 1
    fi
  }
fi

function bh_python_venv_create() {
  deactivate
  if test -d ./venv/bin/; then rm -r ./venv; fi
  python -m venv venv
  if test requirements.txt; then pip install -r requirements.txt; fi
}

function bh_python_venv_load() {
  deactivate
  source venv/bin/activate
  if test requirements.txt; then pip install -r requirements.txt; fi
}

function bh_python_http_host_folder() {
  python -m http.server 80
}

# ---------------------------------------
# jupyter
# ---------------------------------------

if type jupyter &>/dev/null; then
  function bh_python_jupyter_notebook() {
    jupyter notebook
  }

  function bh_python_jupyter_remove_output() {
    jupyter nbconvert --ClearOutputPreprocessor.enabled=True --inplace $@
  }
fi
# ---------------------------------------
# pygmentize
# ---------------------------------------

if type pygmentize &>/dev/null; then
  function bh_python_pygmentize_folder_xml_files_by_extensions_to_jpeg() {
    : ${1?"Usage: ${FUNCNAME[0]} <folder>"}
    find . -maxdepth 1 -name "*.xml" | while read -r i; do
      pygmentize -f jpeg -l xml -o $i.jpg $i
    done
  }
  function bh_python_pygmentize_folder_xml_files_by_extensions_to_rtf() {
    : ${1?"Usage: ${FUNCNAME[0]} <folder>"}

    find . -maxdepth 1 -name "*.xml" | while read -r i; do
      pygmentize -f jpeg -l xml -o $i.jpg $i
      pygmentize -P fontsize=16 -P fontface=consolas -l xml -o $i.rtf $i
    done
  }
  function bh_python_pygmentize_folder_xml_files_by_extensions_to_html() {
    : ${1?"Usage: ${FUNCNAME[0]} ARGUMENT"}
    find . -maxdepth 1 -name "*.xml" | while read -r i; do
      pygmentize -O full,style=default -f html -l xml -o $i.html $i
    done
  }
fi
