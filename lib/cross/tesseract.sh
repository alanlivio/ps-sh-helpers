# ---------------------------------------
# tesseract
# ---------------------------------------

function bh_tesseract_reconize_text_en() {
  : ${1?"Usage: ${FUNCNAME[0]} <image>"}
  tesseract -l eng "$1" "$1.txt"
}

function bh_tesseract_reconize_text_pt() {
  : ${1?"Usage: ${FUNCNAME[0]} <image>"}
  tesseract -l por "$1" "$1.txt"
}

function bh_tesseract_reconize_stdout() {
  : ${1?"Usage: ${FUNCNAME[0]} <image>"}
  tesseract "$1" stdout
}
