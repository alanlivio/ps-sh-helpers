function latex_clean() {
  rm -rf _markdown* *.markdown.lua *.aux *.dvi *.log *.lox *.out *.lol *.pdf *.synctex.gz _minted-* *.bbl *.blg *.lot *.lof *.toc *.lol *.fdb_latexmk *.fls *.bcf
}

function latex_mk_build() {
  : ${1?"Usage: ${FUNCNAME[0]} <main-tex-file>"}
  latexmk --shell-escape -synctex=1 -interaction=nonstopmode -file-line-error $1
}
