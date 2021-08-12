function hf_texlive_install() {
  sudo tlmgr.bat install $@
}

function hf_texlive_install_from_saved_lis() {
  local pkgs_to_install=$(cat $BKP_DOTFILES_DIR/texlive_installed_pkgs.txt | awk '{print substr($2, 1, length($2)-1)}' | tr '\n' ' ')
  sudo tlmgr.bat install $pkgs_to_install
}

function hf_texlive_search_file() {
  sudo tlmgr.bat search -file $1
}

function hf_texlive_list_installed() {
  tlmgr.bat list --only-installed
}

function hf_texlive_save_list_installed() {
  tlmgr.bat list --only-installed >$BKP_DOTFILES_DIR/texlive_installed_pkgs.txt
}

function hf_texlive_gui_tlmgr() {
  tlshell.exe
}
