# ---------------------------------------
# flutter
# ---------------------------------------

function flutter_pkgs_get() {
  flutter pub get
}

function flutter_pkgs_upgrade() {
  flutter packages pub upgrade
}

function flutter_doctor() {
  flutter doctor -v
}

function flutter_run() {
  flutter run
}

function flutter_clean() {
  flutter clean
}

function flutter_scanfoold() {
  flutter create --sample=material.Scaffold.2 mysample
}
