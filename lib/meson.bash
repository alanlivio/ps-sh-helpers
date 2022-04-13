# ---------------------------------------
# meson
# ---------------------------------------

MESON_DIR="_build"

function bh_meson_configure() {
  if test -e meson.build; then
    meson $MESON_DIR 
  else
    meson .. 
  fi
}

function bh_meson_build() {
  ninja
}

function bh_meson_install() {
  ninja install
}
