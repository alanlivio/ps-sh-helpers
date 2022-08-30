YOUTUBEDL_ARGS="--download-archive .downloaded.txt --no-warnings --no-post-overwrites --ignore-errors --prefer-free-formats --merge-output-format webm "

function youtubedl_from_txt() {
  : ${1?"Usage: ${FUNCNAME[0]} <txt_file>"}
  youtube-dl -a "$1" --download-archive .downloaded.txt $YOUTUBEDL_ARGS
}

function youtubedl_video480() {
  : ${1?"Usage: ${FUNCNAME[0]} <txt_file>"}
  youtube-dl "$1" -f 'best[height<=480]' $YOUTUBEDL_ARGS
}

function youtubedl_from_txt_video480() {
  : ${1?"Usage: ${FUNCNAME[0]} <txt_file>"}
  youtube-dl -a "$1" -f 'best[height<=480]' $YOUTUBEDL_ARGS
}

function youtubedl_audio() {
  : ${1?"Usage: ${FUNCNAME[0]} <txt_file>"}
  youtube-dl "$1" $YOUTUBEDL_ARGS --extract-audio --audio-format aac --ignore-errors --embed-thumbnail --output "%(title)s.%(ext)s" --add-metadata
}

function youtubedl_from_txt_audio() {
  : ${1?"Usage: ${FUNCNAME[0]} <txt_file>"}
  youtube-dl -a "$1" $YOUTUBEDL_ARGS --extract-audio --audio-format aac --ignore-errors --embed-thumbnail --output "%(title)s.%(ext)s" --add-metadata
}
