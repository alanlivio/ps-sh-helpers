# ---------------------------------------
# meson
# ---------------------------------------

MESON_DIR="_build"

function bh_meson_configure() {
  meson $MESON_DIR --buildtype=debug
}

function bh_meson_cd_build() {
  if test -d $MESON_DIR; then
    cd $MESON_DIR
  fi
}

function bh_meson_build() {
  bh_meson_cd_build
  ninja
}

function bh_meson_install() {
  bh_meson_cd_build
  ninja install
}
