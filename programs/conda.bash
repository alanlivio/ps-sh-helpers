function conda_clean() {
    conda clean --all --y
}

function conda_env_remove() {
    : ${1?"Usage: ${FUNCNAME[0]} <env_name>"}
    conda env remove -n $1 --y
}

function conda_env_create_python311() {
    : ${1?"Usage: ${FUNCNAME[0]} <env_name>"}
    conda create -n $1 python==3.11 -y
}

alias conda_deactivate="conda deactivate" 
alias conda_env_export_pip_requirements="conda list -e requirements.txt"
alias conda_env_export_to_enviroment_yml="conda env export -f environment.yml"
alias conda_env_create_from_enviroment_yml="conda env create -f environment.yml"
alias conda_env_update_from_enviroment_yml="conda env update -f environment.yml --prune"
