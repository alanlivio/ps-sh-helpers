alias python_clean_cache='find . | grep -E "(/__pycache__$|\.pyc$|\.pyo$)" | xargs rm -rf'

function python_check_tensorflow() {
    python3 -c "import tensorflow as tf; print(tf.config.list_physical_devices('GPU'))"
}

function python_setup_install_local() {
    sudo python setup.py install
}

function python_setup_upload_testpypi() {
    rm -r dist/
    rm -rf ./*.egg-info
    python setup.py bdist_wheel
    twine check dist/*
    twine upload --repository testpypi dist/*
}

function python_setup_upload_pypip() {
    rm -r dist/
    rm -rf ./*.egg-info
    python setup.py bdist_wheel
    twine check dist/*
    twine upload dist/*
}

alias conda_env_export_pip_requirements="conda list -e requirements.txt"
alias conda_env_export_to_enviroment_yml="conda env export -f environment.yml"
alias conda_env_create_from_enviroment_yml="conda env create -f environment.yml"
alias conda_env_update_from_enviroment_yml="conda env update -f environment.yml --prune"
