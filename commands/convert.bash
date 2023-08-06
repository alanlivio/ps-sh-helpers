function convert_heic_to_jpg_at_dir() {
  if test -z "*.heic"; then
    for file in *.heic; do convert $file ${file/%.heic/.jpg}; done
  else
    log_msg "no .heic file at dir"
  fi
}


function convert_pptx_compress_images_inplace(){
  [[ -d xtractd ]] && rm -r xtractd
  unzip "$1" -d xtractd
  cd xtractd/ppt/media
  mogrify -resize 70% *.png
  mogrify -resize 70% *.jpeg
  mogrify -resize 70% *.gif
  cd ..
  # fix linked files
  sed -i '' -e 's/\(Target="[^"]*\)tiff"/\1png"/g' slides/_rels/*.rels
  sed -i '' -e 's/\(Target="[^"]*\)tiff"/\1gif"/g' slides/_rels/*.rels
  sed -i '' -e 's/\(Target="[^"]*\)tiff"/\1jpeg"/g' slides/_rels/*.rels
  cd ..
  # create file
  rm "../$1"
  zip -r "../$1" *
  cd ..
  # remove uncompressed folder
  rm -r xtractd
}