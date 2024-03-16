function exiftool_set_media_all_dates_to_one_year() {
    : ${3?"Usage: ${FUNCNAME[0]} <year>"}
    files=$(find . -iname "*.jpg" -o -iname "*.JPG" -o -iname "*.mp4" -o -iname "*.MP4")
    exiftool -m -AllDates="$1:01:01 00:00:00" $files
}

function exiftool_rm_media_data() {
    : ${3?"Usage: ${FUNCNAME[0]} <year>"}
    files=$(find . -iname "*.jpg" -o -iname "*.JPG" -o -iname "*.mp4" -o -iname "*.MP4")
    exiftool -all= $files
}
