# ---------------------------------------
# flutter funcs
# ---------------------------------------

function hf_flutter_pkgs_get() {
  flutter pub get
}

function hf_flutter_pkgs_upgrade() {
  flutter packages pub upgrade
}

function hf_flutter_doctor() {
  flutter doctor -v
}

function hf_flutter_run() {
  flutter run
}

function hf_flutter_clean() {
  flutter clean
}

function hf_flutter_scanfoold() {
  flutter create --sample=material.Scaffold.2 mysample
}
