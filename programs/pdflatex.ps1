function latex_clean() {
    Remove-Item -f comment.cut ./*.aux ./*.dbx ./*.bbx ./*.cbx ./*.dvi ./*.log ./*.lox ./*.out ./*.lol ./*.pdf ./*.synctex.gz ./_minted-* ./*.bbl ./*.blg ./*.lot ./*.lof ./*.toc ./*.lol ./*.fdb_latexmk ./*.fls ./*.bcf ./*.aux ./*.fls ./*.fdb_latexmk ./*.log
}

function latex_word_count() {
    if ($PSBoundParameters.Keys.Count -lt 1) { log_error "Usage: latex_word_count<file.tex>"; }
    (texcount -inc -sum $file 2>$null) |
    ForEach-Object {
        if ($_ -match '^Sum count:\s*(\d+)') { $matches[1] }
    }
}