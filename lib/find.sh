# ---------------------------------------
# find
# ---------------------------------------

function hf_find_duplicated_pdf() {
  find . -iname "*.pdf" -not -empty -type f -printf "%s\n" | sort -rn | uniq -d | xargs -I{} -n1 find . -type f -size {}c -print0 | xargs -r -0 md5sum | sort | uniq -w32 --all-repeated=separate
}
