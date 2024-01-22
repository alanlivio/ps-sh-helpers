function convert_heic_at_folder_to_jpg() {
    if test -n "*.heic"; then
        for file in *.heic; do convert $file ${file/%.heic/.jpg}; done
    else
        _log_msg "no .heic file at dir"
    fi
}

function convert_pptx_to_compressed_images_pptx() {
    : ${1?"Usage: ${FUNCNAME[0]} <pptx_file>"}
    # https://dev.to/feldroy/til-strategies-for-compressing-jpg-files-with-imagemagick-5fn9
    [[ -d /tmp/pptx_extracted ]] && rm -rf /tmp/pptx_extracted/
    [[ -d ${1%.*}-compressed.pptx ]] && rm -rf ${1%.*}-compressed.pptx
    unzip -q "$1" -d /tmp/pptx_extracted
    local large_images=$(find /tmp/pptx_extracted/ppt/media -type f -size +500k -name *.jpg -o -name *.png -o -name *.jpeg -print)
    local mogrigfy_params="-sampling-factor 4:2:0 -quality 85 -strip"
    [[ -z $large_images ]] && _log_msg "no large images" && return
    for image in $large_images; do
        _log_msg "compressing $(basename $image)"
        mogrify $mogrigfy_params $image
    done
    # create file
    local cwd=$(pwd)
    (
        cd /tmp/pptx_extracted/
        zip -9 -q -r "$cwd/${1%.*}-compressed.pptx" *
    )
}
