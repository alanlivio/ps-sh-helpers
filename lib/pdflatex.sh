function bh_latex_clean() {
  rm -rf ./*.aux ./*.dvi ./*.log ./*.lox ./*.out ./*.lol ./*.pdf ./*.synctex.gz ./_minted-* ./*.bbl ./*.blg ./*.lot ./*.lof ./*.toc ./*.lol ./*.fdb_latexmk ./*.fls ./*.bcf
}

function bh_latex_gitignore() {
  bh_git_gitignore_create latex >.gitignore
  echo "main.pdf" >>.gitignore
  echo "_main*.pdf" >>.gitignore
}

function bh_latex_build_pdflatex() {
  : ${1?"Usage: ${FUNCNAME[0]} <main-tex-file>"}
  pdflatex --shell-escape -synctex=1 -interaction=nonstopmode -file-line-error $1 \
    && find . -maxdepth 1 -name "*.aux" -exec echo -e "\n-- bibtex" {} \; -exec bibtex {} \; \
    && pdflatex --shell-escape -synctex=1 -interaction=nonstopmode -file-line-error $1
}
