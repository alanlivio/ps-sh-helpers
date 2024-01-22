function cmake_configure_debug() {
    if test -e CMakeLists.txt; then
        cmake -B _build-Debug-$WSL_DISTRO_NAME$OS -G Ninja -DCMAKE_EXPORT_COMPILE_programs:BOOL=TRUE -DSTATIC_LINKING=OFF -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Debug "$@"
    else
        cmake .. -G Ninja -DCMAKE_EXPORT_COMPILE_programs:BOOL=TRUE -DSTATIC_LINKING=OFF -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Debug "$@"
    fi
}

function cmake_configure_release() {
    if test -e CMakeLists.txt; then
        cmake -B _build-Release-$WSL_DISTRO_NAME$OS -G Ninja -DCMAKE_EXPORT_COMPILE_programs:BOOL=TRUE -DSTATIC_LINKING=OFF -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release "$@"
    else
        cmake .. -G Ninja -DCMAKE_EXPORT_COMPILE_programs:BOOL=TRUE -DSTATIC_LINKING=OFF -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release "$@"
    fi
}

function cmake_build() {
    cmake --build . --target all
}

function cmake_clean() {
    cmake --build . --target clean
}

function cmake_build_target() {
    : ${1?"Usage: ${FUNCNAME[0]} <target>"}
    cmake --build . --target $1
}

function cmake_check() {
    cmake --build . --target check
}

function cmake_install() {
    case $OSTYPE in
    linux*)
        sudo cmake --install . --prefix /usr
        ;;
    msys*)
        cmake --install .
        ;;
    *)
        sudo cmake --install .
        ;;
    esac
}

function cmake_uninstall() {
    local manifest="install_manifest.txt"
    if test -e $manifest; then
        while IFS= read -r i; do
            local file=${i%$'\r'}
            if test -e "$file"; then
                _log_msg "uninstall $file"
                sudo rm "$file"
            fi
        done <$manifest
    else
        _log_error "$manifest does not exist" && return 1
    fi
}

function cmake_clean_retain_objs() {
    if test -d CMakeFiles; then
        find . -maxdepth 1 -not -name '.' -not -name CMakeFiles -exec rm -rf {} \;
    else
        _log_error "there is no CMakeFiles dir" && return 1
    fi
}

function cmake_test_all() {
    ctest
}

function cmake_test_target() {
    : ${1?"Usage: ${FUNCNAME[0]} <target>"}
    cmake --build . --target $1
    ctest -R $1
}
