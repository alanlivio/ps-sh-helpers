# https://www.makeuseof.com/install-hyper-v-windows-11-home/
function log_msg() { Write-Host -ForegroundColor DarkYellow "--" ($args -join " ") }

log_msg "enable hyper-v"
$dir = "${env:SystemRoot}\servicing\Packages"
$pkgs = Get-ChildItem $dir\* -Include *Hyper-V*.mum | Select Name
foreach ($pkg in $pkgs) {
    $path = '"' + $dir + '\' + $pkg.Name + '"'
    gsudo dism /online /norestart /add-package:$path
}
gsudo dism /online /enable-feature /featurename:Microsoft-Hyper-V -All /LimitAccess /ALL