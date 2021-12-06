# ---------------------------------------
# image
# ---------------------------------------

function bh_imagem_compress() {
  : ${1?"Usage: ${FUNCNAME[0]} <image>"}
  pngquant "$1" --force --quality=70-80 -o "compressed-$1"
}

function bh_imagem_compress_hard() {
  : ${1?"Usage: ${FUNCNAME[0]} <image>"}
  jpegoptim -d . $1.jpeg
}
