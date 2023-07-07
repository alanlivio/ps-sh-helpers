function pandoc_from_any_to_markdown() {
  : ${1?"Usage: ${FUNCNAME[0]} <file_name>"}
  pandoc -s $1 -t markdown -o ${1%.*}.md
}

function pandoc_from_docx_to_latex() {
  : ${1?"Usage: ${FUNCNAME[0]} <file_name>"}
  pandoc -s $1 -f docx -t latex -o ${1%.*}.tex
}
