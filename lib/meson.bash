MESON_DIR="_build"

function meson_configure() {
  if test -e meson.build; then
    meson $MESON_DIR
  else
    meson ..
  fi
}

function meson_build() {
  ninja
}

function meson_install() {
  ninja install
}
