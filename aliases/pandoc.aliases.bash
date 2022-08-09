function pandoc_convert_to_markdown() {
  : ${1?"Usage: ${FUNCNAME[0]} <file_name>"}
  pandoc -s $1 -t markdown -o ${1%.*}.md
}
