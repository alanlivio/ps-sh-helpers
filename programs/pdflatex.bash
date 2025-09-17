function latex_clean() {
    rm -f comment.cut ./*.aux ./*.dbx ./*.bbx ./*.cbx ./*.dvi ./*.log ./*.lox ./*.out ./*.lol ./*.pdf ./*.synctex.gz ./_minted-* ./*.bbl ./*.blg ./*.lot ./*.lof ./*.toc ./*.lol ./*.fdb_latexmk ./*.fls ./*.bcf ./*.aux ./*.fls ./*.fdb_latexmk ./*.log
}

function latex_word_count(){
    : ${1?"Usage: ${FUNCNAME[0]} <file.tex>"}
    texcount -inc -sum $1 | awk -F': ' '/^Sum count:/ {print $2}'
}