function gs_compress() {
  : ${1?"Usage: ${FUNCNAME[0]} <pdf>"}
  gs -sDEVICE=pdfwrite -dCompatibilityLevel=1.4 -dNOPAUSE -dQUIET -dBATCH -sOutputFile=${1%.*}-compressed.pdf $1
}

function gs_compress_hard1() {
  : ${1?"Usage: ${FUNCNAME[0]} <pdf>"}
  gs -sDEVICE=pdfwrite -dCompatibilityLevel=1.4 -dNOPAUSE -dQUIET -dBATCH -dPDFSETTINGS=//printer -dColorImageResolution=200 -sOutputFile=${1%.*}-compressed.pdf $1
}

function gs_compress_hard2() {
  : ${1?"Usage: ${FUNCNAME[0]} <pdf>"}
  gs -sDEVICE=pdfwrite -dCompatibilityLevel=1.4 -dNOPAUSE -dQUIET -dBATCH -dPDFSETTINGS=//ebook -sOutputFile=${1%.*}-compressed.pdf $1
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
