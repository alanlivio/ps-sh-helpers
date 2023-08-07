# gs_compress ref
# https://stackoverflow.com/questions/46195795/ghostscript-pdf-batch-compression

function gs_compress() {
  : ${1?"Usage: ${FUNCNAME[0]} <pdf>"}
  gs -dNOPAUSE -dQUIET -dBATCH -sDEVICE=pdfwrite -sOutputFile=${1%.*}-compressed.pdf $1 -dPDFSETTINGS=/ebook -dColorImageResolution=200
}

function gs_compress_hard() {
  : ${1?"Usage: ${FUNCNAME[0]} <pdf>"}
  gs -dNOPAUSE -dQUIET -dBATCH -sDEVICE=pdfwrite -sOutputFile=${1%.*}-compressed.pdf $1 -dPDFSETTINGS=/screen
}

function gs_concat() {
  : ${2?"Usage: ${FUNCNAME[0]} <pdf_1> <pdf_2>"}
  gs -dNOPAUSE -dQUIET -dBATCH -sDEVICE=pdfwrite -sOUTPUTFILE=${1%.*}-${2%.*}-concat.pdf $1 $2
}

function gs_concat() {
  : ${2?"Usage: ${FUNCNAME[0]} <pdf_1> <pdf_2>"}
  gs -dNOPAUSE -dQUIET -dBATCH -sDEVICE=pdfwrite -sOUTPUTFILE=${1%.*}-${2%.*}-concat.pdf $1 $2
}

function gs_remove_annotations() {
  : ${1?"Usage: ${FUNCNAME[0]} <pdf>"}
  gs -dNOPAUSE -dQUIET -dBATCH -sDEVICE=pdfwrite -dShowAnnots=false -sOutputFile=${1%.*}-nocomments.pdf $1
}
