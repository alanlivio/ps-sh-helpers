alias python_clean_cache='find . | grep -E "(/__pycache__$|\.pyc$|\.pyo$)" | xargs rm -rf'

function pip_install() {
    for pkg in $@; do
        pip show $pkg >/dev/null || pip install -U $pkg
    done
}

function python_check_tensorflow() {
    python3 -c "import tensorflow as tf; print(tf.config.list_physical_devices('GPU'))"
}

function python_check_numa() {
    type -p numactl >/dev/null || sudo apt-get install numactl
    numactl --show
}

function python_packaging_install_local() {
    [[ -d dist ]] && rm -r dist
    [[ -d build ]] && rm -r dist
    python -m build . --wheel
    pip install dist/*.whl
}

function python_packaging_upload_testpypi() {
    type -p numactl >/dev/null || pip install twine
    [[ -d dist ]] && rm -r dist
    [[ -d build ]] && rm -r dist
    rm -rf ./*.egg-info
    python -m build . --wheel
    twine check dist/*
    twine upload --repository testpypi dist/*
}

function python_packaging_upload_pypip() {
    type -p numactl >/dev/null || pip install twine
    [[ -d dist ]] && rm -r dist
    [[ -d build ]] && rm -r dist
    python -m build . --wheel
    twine check dist/*
    twine upload dist/*
}

function python_pyright_stubs_from_requirements_txt() {
    type -p pyright >/dev/null || pip install pyright
    pip show requirements-parser >/dev/null || pip install requirements-parser
    local pkgs=$(python -c "import requirements; import os; names=[req.name for req in requirements.parse(open('requirements.txt', 'r'))]; print(' '.join(names))")
    for pkg in $pkgs; do
        pyright --createstub $pkg
    done
}

alias conda_env_export_pip_requirements="conda list -e requirements.txt"
alias conda_env_export_to_enviroment_yml="conda env export -f environment.yml"
alias conda_env_create_from_enviroment_yml="conda env create -f environment.yml"
alias conda_env_update_from_enviroment_yml="conda env update -f environment.yml --prune"
