# ---------------------------------------
# youtube-dl
# ---------------------------------------

YOUTUBEDL_ARGS="--download-archive .downloaded.txt --no-warnings --no-post-overwrites --ignore-errors"

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
  youtube-dl "$1" $YOUTUBEDL_ARGS -f bestaudio --extract-audio --audio-format mp3 --audio-quality 0 --ignore-errors --embed-thumbnail --output "%(title)s.%(ext)s" --metadata-from-title "%(artist)s - %(title)s" --add-metadata
}

function youtubedl_from_txt_audio() {
  : ${1?"Usage: ${FUNCNAME[0]} <txt_file>"}
  youtube-dl -a "$1" $YOUTUBEDL_ARGS -f bestaudio --extract-audio --audio-format mp3 --audio-quality 0 --ignore-errors --embed-thumbnail --output "%(title)s.%(ext)s" --metadata-from-title "%(artist)s - %(title)s" --add-metadata
}
