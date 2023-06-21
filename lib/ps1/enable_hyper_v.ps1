# https://www.makeuseof.com/install-hyper-v-windows-11-home/
$dir="${env:SystemRoot}\servicing\Packages"
$pkgs=Get-ChildItem $dir\* -Include *Hyper-V*.mum | Select Name
foreach ($pkg in $pkgs) {
  $path='"' + $dir + '\' + $pkg.Name + '"'
  dism /online /norestart /add-package:$path
}
dism /online /enable-feature /featurename:Microsoft-Hyper-V -All /LimitAccess /ALL