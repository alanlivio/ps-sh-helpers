function convert_heic_to_jpg_at_dir() {
  if test -z "*.heic"; then
    for file in *.heic; do convert $file ${file/%.heic/.jpg}; done
  else
    log_msg "no .heic file at dir"
  fi
}