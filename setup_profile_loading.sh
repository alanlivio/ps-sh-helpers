function log_msg() { echo -e "\033[00;33m-- $* \033[00m"; }

HELPERS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
init_profile="$HELPERS_DIR/init.sh"

if ! grep -q "^source $init_profile\\b" ~/.bashrc; then
    echo "source $init_profile" >> ~/.bashrc
    log_msg "$HELPERS_DIR/init.bash added to ~/.bashrc"
else
    log_msg "$HELPERS_DIR/init.bash already exists at ~/.bashrc"
fi