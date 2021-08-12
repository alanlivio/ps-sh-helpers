# ---------------------------------------
# pdftk helpers
# ---------------------------------------

function bh_pdf_concat() {
  : ${2?"Usage: ${FUNCNAME[0]} <pdf_1> <pdf_2>"}
  pdftk $1 $2 cat output ${1%.*}-concatenated.pdf
}

function bh_pdf_remove_watermark() {
  : ${1?"Usage: ${FUNCNAME[0]} <pdf>"}
  sed -e "s/THISISTHEWATERMARK/ /g" <"$1" >nowatermark.pdf
  pdftk nowatermark.pdf output repaired.pdf
  mv repaired.pdf nowatermark.pdf
}

function bh_pdf_compress() {
  : ${1?"Usage: ${FUNCNAME[0]} <pdf>"}
  ghostscript -sDEVICE=pdfwrite -dCompatibilityLevel=1.4 -dNOPAUSE -dQUIET -dBATCH -sOutputFile=${1%.*}-compressed.pdf $1
}

function bh_pdf_compress_hard1() {
  : ${1?"Usage: ${FUNCNAME[0]} <pdf>"}
  ghostscript -sDEVICE=pdfwrite -dCompatibilityLevel=1.4 -dNOPAUSE -dQUIET -dBATCH -dPDFSETTINGS=/printer -sOutputFile=${1%.*}-compressed.pdf $1
}

function bh_pdf_compress_hard2() {
  : ${1?"Usage: ${FUNCNAME[0]} <pdf>"}
  ghostscript -sDEVICE=pdfwrite -dCompatibilityLevel=1.4 -dNOPAUSE -dQUIET -dBATCH -dPDFSETTINGS=/ebook -sOutputFile=${1%.*}-compressed.pdf $1
}

# ---------------------------------------
# others pdf helpers
# ---------------------------------------

function bh_pdf_count_words() {
  : ${1?"Usage: ${FUNCNAME[0]} <pdf>"}
  pdftotext $1 - | wc -w
}

function bh_pdf_remove_annotations() {
  : ${1?"Usage: ${FUNCNAME[0]} <pdf>"}
  rewritepdf "$1" "-no-annotations-$1"
}

function bh_pdf_search_pattern() {
  : ${1?"Usage: ${FUNCNAME[0]} <pdf>"}
  pdfgrep -rin "$1" | while read -r i; do basename "${i%%:*}"; done | sort -u
}

function bh_pdf_remove_password() {
  : ${1?"Usage: ${FUNCNAME[0]} <pdf>"}
  qpdf --decrypt "$1" "unlocked-$1"
}