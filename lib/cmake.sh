# ---------------------------------------
# cmake funcs
# ---------------------------------------

CMAKE_DIR="_build-Debug-$WSL_DISTRO_NAME$OS"
CMAKE_DIR_RELEASE="_build-Release-$WSL_DISTRO_NAME$OS"
CMAKE_CONFIG_ARGS="
  -DCMAKE_RULE_MESSAGES=OFF 
  -DCMAKE_TARGET_MESSAGES=OFF 
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
  -DSTATIC_LINKING=OFF 
  -DBUILD_SHARED_LIBS=ON 
  "
function hf_cmake_args_default() {
  echo $CMAKE_CONFIG_ARGS
}

function hf_cmake_configure() {
  if test -f CMakeLists.txt; then
    cmake -B $CMAKE_DIR -G Ninja $CMAKE_CONFIG_ARGS -DCMAKE_BUILD_TYPE=Debug $@
  else
    cmake .. -G Ninja $CMAKE_CONFIG_ARGS -DCMAKE_BUILD_TYPE=Debug $@
  fi
}

function hf_cmake_configure_release() {
  if test -f CMakeLists.txt; then
    cmake -B $CMAKE_DIR_RELEASE -G Ninja $CMAKE_CONFIG_ARGS -DCMAKE_BUILD_TYPE=Release $@
  else
    cmake .. -G Ninja $CMAKE_CONFIG_ARGS -DCMAKE_BUILD_TYPE=Release $@
  fi
}

function hf_cmake_build() {
  cmake --build . --target all
}

function hf_cmake_clean() {
  cmake --build . --target clean
}

function hf_cmake_build_target() {
  cmake --build . --target $1
}

function hf_cmake_check() {
  cmake --build . --target check
}

function hf_cmake_install() {
  if $IS_WINDOWS_MSYS; then
    cmake --install . --prefix /mingw64
  elif $IS_LINUX; then
    sudo cmake --install . --prefix /usr
  else
    sudo cmake --install .
  fi
}

function hf_cmake_uninstall() {
  local manifest="install_manifest.txt"
  if test -f $manifest; then
    cat $manifest | while read -r i; do
      if test -f $i; then sudo rm -f $i; fi
    done
  else
    hf_log_error "$manifest does not exist"
  fi
}

function hf_cmake_clean_retain_objs() {
  if test -d CMakeFiles; then
    find . -maxdepth 1 -not -name '.' -not -name CMakeFiles -exec rm -rf {} \;
  else
    hf_log_error "there is no CMakeFiles folder"
  fi
}

function hf_cmake_test_all() {
  ctest
}

function hf_cmake_test_target() {
  cmake --build . --target $1
  ctest -R $1
}
