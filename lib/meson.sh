# ---------------------------------------
# meson funcs
# ---------------------------------------

MESON_DIR="_build"

function hf_meson_configure() {
  meson $MESON_DIR --buildtype=debug
}

function hf_meson_cd_build() {
  if test -d $MESON_DIR; then
    cd $MESON_DIR
  fi
}

function hf_meson_build() {
  hf_meson_cd_build
  ninja
}

function hf_meson_install() {
  hf_meson_cd_build
  ninja install
}
