# ---------------------------------------
# cmake
# ---------------------------------------

CMAKE_DIR="_build-Debug-$WSL_DISTRO_NAME$OS"
CMAKE_DIR_RELEASE="_build-Release-$WSL_DISTRO_NAME$OS"
CMAKE_CONFIG_ARGS="
  -DCMAKE_RULE_MESSAGES=OFF 
  -DCMAKE_TARGET_MESSAGES=OFF 
  -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=TRUE 
  -DSTATIC_LINKING=OFF 
  -DBUILD_SHARED_LIBS=ON 
  "
function bh_cmake_args_default() {
  echo $CMAKE_CONFIG_ARGS
}

function bh_cmake_configure() {
  if test -e CMakeLists.txt; then
    cmake -B $CMAKE_DIR -G Ninja $CMAKE_CONFIG_ARGS -DCMAKE_BUILD_TYPE=Debug $@
  else
    cmake .. -G Ninja $CMAKE_CONFIG_ARGS -DCMAKE_BUILD_TYPE=Debug $@
  fi
}

function bh_cmake_configure_release() {
  if test -e CMakeLists.txt; then
    cmake -B $CMAKE_DIR_RELEASE -G Ninja $CMAKE_CONFIG_ARGS -DCMAKE_BUILD_TYPE=Release $@
  else
    cmake .. -G Ninja $CMAKE_CONFIG_ARGS -DCMAKE_BUILD_TYPE=Release $@
  fi
}

function bh_cmake_build() {
  cmake --build . --target all
}

function bh_cmake_clean() {
  cmake --build . --target clean
}

function bh_cmake_build_target() {
  cmake --build . --target $1
}

function bh_cmake_check() {
  cmake --build . --target check
}

function bh_cmake_install() {
  if $IS_WIN_MSYS; then
    cmake --install . --prefix /mingw64
  elif $IS_LINUX; then
    sudo cmake --install . --prefix /usr
  else
    sudo cmake --install .
  fi
}

function bh_cmake_uninstall() {
  local manifest="install_manifest.txt"
  if test -e $manifest; then
    while IFS= read -r i; do
      local file=${i%$'\r'}
      if test -e "$file"; then sudo rm $file; fi
    done <$manifest
  else
    bh_log_error "$manifest does not exist"
  fi
}

function bh_cmake_clean_retain_objs() {
  if test -d CMakeFiles; then
    find . -maxdepth 1 -not -name '.' -not -name CMakeFiles -exec rm -rf {} \;
  else
    bh_log_error "there is no CMakeFiles folder"
  fi
}

function bh_cmake_test_all() {
  ctest
}

function bh_cmake_test_target() {
  cmake --build . --target $1
  ctest -R $1
}
