function pngquant_compress() {
  : ${1?"Usage: ${FUNCNAME[0]} <image>"}
  pngquant "$1" --force --quality=70-80 -o "compressed-$1"
}
