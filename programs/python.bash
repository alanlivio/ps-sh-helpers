alias python_clean_cache='find . | grep -E "(/__pycache__$|\.pyc$|\.pyo$)" | xargs rm -rf'

function python_check_tensorflow() {
    python3 -c "import tensorflow as tf; print(tf.config.list_physical_devices('GPU'))"
}

function python_packaging_install_local() {
    [[ -d dist ]] && rm -r dist
    [[ -d build ]] && rm -r dist
    python -m build . --wheel
    pip install dist/*.whl
}

function python_packaging_upload_testpypi() {
    [[ -d dist ]] && rm -r dist
    [[ -d build ]] && rm -r dist
    rm -rf ./*.egg-info
    python -m build . --wheel
    twine check dist/*
    twine upload --repository testpypi dist/*
}

function python_packaging_upload_pypip() {
    [[ -d dist ]] && rm -r dist
    [[ -d build ]] && rm -r dist
    python -m build . --wheel
    twine check dist/*
    twine upload dist/*
}

alias conda_env_export_pip_requirements="conda list -e requirements.txt"
alias conda_env_export_to_enviroment_yml="conda env export -f environment.yml"
alias conda_env_create_from_enviroment_yml="conda env create -f environment.yml"
alias conda_env_update_from_enviroment_yml="conda env update -f environment.yml --prune"
