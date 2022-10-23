YOUTUBEDL_ARGS="--download-archive .downloaded.txt --no-warnings --add-metadata --no-post-overwrites --ignore-errors "

function youtube-dl_video480() {
  : ${1?"Usage: ${FUNCNAME[0]} <uld>"}
  youtube-dl "$1" -f 'best[height<=480]' $YOUTUBEDL_ARGS
}

function youtube-dl_video480_from_txt() {
  : ${1?"Usage: ${FUNCNAME[0]} <txt_file>"}
  youtube-dl -a "$1" -f 'best[height<=480]' $YOUTUBEDL_ARGS
}

function youtube-dl_audio() {
  : ${1?"Usage: ${FUNCNAME[0]} <txt_file>"}
  youtube-dl "$1" --extract-audio $YOUTUBEDL_ARGS
}
