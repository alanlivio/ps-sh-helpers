# ---------------------------------------
# ghostscript
# ---------------------------------------

function ghostscript_compress() {
  : ${1?"Usage: ${FUNCNAME[0]} <pdf>"}
  ghostscript -sDEVICE=pdfwrite -dCompatibilityLevel=1.4 -dNOPAUSE -dQUIET -dBATCH -sOutputFile=${1%.*}-compressed.pdf $1
}

function ghostscript_compress_hard1() {
  : ${1?"Usage: ${FUNCNAME[0]} <pdf>"}
  ghostscript -sDEVICE=pdfwrite -dCompatibilityLevel=1.4 -dNOPAUSE -dQUIET -dBATCH -dPDFSETTINGS=//printer -dColorImageResolution=200 -sOutputFile=${1%.*}-compressed.pdf $1
}

function ghostscript_compress_hard2() {
  : ${1?"Usage: ${FUNCNAME[0]} <pdf>"}
  ghostscript -sDEVICE=pdfwrite -dCompatibilityLevel=1.4 -dNOPAUSE -dQUIET -dBATCH -dPDFSETTINGS=//ebook -sOutputFile=${1%.*}-compressed.pdf $1
}

function ghostscript_concat() {
  : ${2?"Usage: ${FUNCNAME[0]} <pdf_1> <pdf_2>"}
  ghostscript -dNOPAUSE -dQUIET -dBATCH -sDEVICE=pdfwrite -sOUTPUTFILE=${1%.*}-${2%.*}-concat.pdf $1 $2
}

function ghostscript_concat() {
  : ${2?"Usage: ${FUNCNAME[0]} <pdf_1> <pdf_2>"}
  ghostscript -dNOPAUSE -dQUIET -dBATCH -sDEVICE=pdfwrite -sOUTPUTFILE=${1%.*}-${2%.*}-concat.pdf $1 $2
}

function ghostscript_remove_annotations() {
  : ${1?"Usage: ${FUNCNAME[0]} <pdf>"}
  ghostscript -dNOPAUSE -dQUIET -dBATCH -sDEVICE=pdfwrite -dShowAnnots=false -sOutputFile=${1%.*}-nocomments.pdf $1
}
