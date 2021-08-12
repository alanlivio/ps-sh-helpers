# ---------------------------------------
# flutter helpers
# ---------------------------------------

function bh_flutter_pkgs_get() {
  flutter pub get
}

function bh_flutter_pkgs_upgrade() {
  flutter packages pub upgrade
}

function bh_flutter_doctor() {
  flutter doctor -v
}

function bh_flutter_run() {
  flutter run
}

function bh_flutter_clean() {
  flutter clean
}

function bh_flutter_scanfoold() {
  flutter create --sample=material.Scaffold.2 mysample
}
