function lxc_list_all() {
    lxc image list
    lxc network list
    lxc list
}

function lxc_image_import() {
    : ${2?"Usage: ${FUNCNAME[0]} <image.tar.gz> <alias>"}
    lxc image import "$1" --alias $2
}

function lxc_profile_assign() {
    : ${2?"Usage: ${FUNCNAME[0]} <image_name> <profile_name,...>"}
    local image_name=$1
    shift
    lxc assign $image_name "$@"
}

function lxc_launch() {
    : ${2?"Usage: ${FUNCNAME[0]} <image_name> <lxc_name>"}
    lxc launch "$1" $2
}

function lxc_pull_file() {
    : ${2?"Usage: ${FUNCNAME[0]} <lxc_name> <lxc_file>"}
    lxc file pull $1/$2 .
}

function lxc_share_dir_home_to_home() {
    : ${2?"Usage: ${FUNCNAME[0]} <lxc_name> <lxc_dir> <local_dir>"}
    lxc config device add "$1" dev disk source=/home/$2 path=/home/ubuntu/$3
    lxc image import "$1" --alias $2
}

function lxc_share_dir_remove() {
    : ${2?"Usage: ${FUNCNAME[0]} <lxc_name> <lxc_dir>"}
    lxc config device remove "$1" $2
}

function lxc_login_as_ubuntu_user() {
    : ${2?"Usage: ${FUNCNAME[0]} <lxc_name>"}
    lxc exec "$1" -- sudo --user ubuntu --login
}
