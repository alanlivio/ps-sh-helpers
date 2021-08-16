# ---------------------------------------
# appx helpers
# ---------------------------------------

function bh_appx_list_installed() {
  sudo powershell -c "Get-AppxPackage -AllUsers | Select-Object Name, PackageFullName"
}

bh_ps_def_func_admin bh_appx_install
bh_ps_def_func_admin bh_appx_uninstall

function bh_appx_install_essentials() {
  local pkgs='Microsoft.WindowsStore Microsoft.WindowsCalculator Microsoft.Windows.Photos Microsoft.WindowsFeedbackHub Microsoft.WindowsCamera Microsoft.WindowsSoundRecorder'
  bh_appx_install $pkgs
}
