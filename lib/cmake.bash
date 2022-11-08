CMAKE_DIR="_build-Debug-$WSL_DISTRO_NAME$OS"
CMAKE_DIR_RELEASE="_build-Release-$WSL_DISTRO_NAME$OS"
CMAKE_ARGS_CONFIG="
  -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE 
  -DSTATIC_LINKING=OFF 
  -DBUILD_SHARED_LIBS=ON 
  "

function cmake_configure_debug() {
  if test -e CMakeLists.txt; then
    cmake -B $CMAKE_DIR -G Ninja $CMAKE_ARGS_CONFIG -DCMAKE_BUILD_TYPE=Debug $@
  else
    cmake .. -G Ninja $CMAKE_ARGS_CONFIG -DCMAKE_BUILD_TYPE=Debug $@
  fi
}

function cmake_configure_release() {
  if test -e CMakeLists.txt; then
    cmake -B $CMAKE_DIR_RELEASE -G Ninja $CMAKE_ARGS_CONFIG -DCMAKE_BUILD_TYPE=Release $@
  else
    cmake .. -G Ninja $CMAKE_ARGS_CONFIG -DCMAKE_BUILD_TYPE=Release $@
  fi
}

function cmake_build() {
  cmake --build . --target all
}

function cmake_clean() {
  cmake --build . --target clean
}

function cmake_build_target() {
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
        echo "uninstall $file"
        sudo rm "$file"
      fi
    done <$manifest
  else
    log_error "$manifest does not exist"
  fi
}

function cmake_clean_retain_objs() {
  if test -d CMakeFiles; then
    find . -maxdepth 1 -not -name '.' -not -name CMakeFiles -exec rm -rf {} \;
  else
    log_error "there is no CMakeFiles dir"
  fi
}

function cmake_test_all() {
  ctest
}

function cmake_test_target() {
  cmake --build . --target $1
  ctest -R $1
}
