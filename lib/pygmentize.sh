# ---------------------------------------
# pygmentize
# ---------------------------------------
function bh_pygmentize_folder_xml_files_by_extensions_to_jpeg() {
  : ${1?"Usage: ${FUNCNAME[0]} <folder>"}
  find . -maxdepth 1 -name "*.xml" | while read -r i; do
    pygmentize -f jpeg -l xml -o $i.jpg $i
  done
}

function bh_pygmentize_folder_xml_files_by_extensions_to_rtf() {
  : ${1?"Usage: ${FUNCNAME[0]} <folder>"}

  find . -maxdepth 1 -name "*.xml" | while read -r i; do
    pygmentize -f jpeg -l xml -o $i.jpg $i
    pygmentize -P fontsize=16 -P fontface=consolas -l xml -o $i.rtf $i
  done
}

function bh_pygmentize_folder_xml_files_by_extensions_to_html() {
  : ${1?"Usage: ${FUNCNAME[0]} ARGUMENT"}
  find . -maxdepth 1 -name "*.xml" | while read -r i; do
    pygmentize -O full,style=default -f html -l xml -o $i.html $i
  done
}
