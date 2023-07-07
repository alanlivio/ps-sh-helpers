YOUTUBEDL_ARGS="-ci --download-archive .downloaded.txt --no-warnings --add-metadata "

function youtube-dl_sub_en() {
  : ${1?"Usage: ${FUNCNAME[0]} <url to video>"}
  local url=${1%%&*} # remove all after & (to leave only www.youtube.com/watch?v=...)
  youtube-dl --write-sub --skip-download --no-playlist --sub-langs en "$url"
}

function youtube-dl_audio() {
  : ${1?"Usage: ${FUNCNAME[0]} <url to audio or list>"}
  youtube-dl $1 --extract-audio --audio-format mp3 -o "%(title)s.%(ext)s" $YOUTUBEDL_ARGS
}

function youtube-dl_video_480p() {
  : ${1?"Usage: ${FUNCNAME[0]} <url to video or list>"}
  youtube-dl -f 'best[height<=480]' --recode-video mp4 $YOUTUBEDL_ARGS "$1"
}

function youtube-dl_video_480p_from_txt() {
  : ${1?"Usage: ${FUNCNAME[0]} <txt_file>"}
  youtube-dl -a "$1" -f 'best[height<=480]' --recode-video mp4 $YOUTUBEDL_ARGS
}
