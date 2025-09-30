HELPERS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
init_profile="$HELPERS_DIR/init.sh"
eval "grep -q '^source $init_profile\\b' ~/.bashrc || echo 'source $init_profile' >> ~/.bashrc"