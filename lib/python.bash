alias python_clean_cache='find . | grep -E "(/__pycache__$|\.pyc$|\.pyo$)" | xargs rm -rf'

function python_check_tensorflow() {
  python3 -c "import tensorflow as tf; print(tf.config.list_physical_devices('GPU'))"
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

alias conda_env_create_from_enviroment_yml="conda env create -f environment.yml"
alias conda_env_update_fromenviroment_yml="conda env update --file environment.yml --prune"