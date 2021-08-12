YOUTUBEDL_PARAMS="--download-archive .downloaded.txt --no-warnings --no-post-overwrites --ignore-errors"
  function bh_youtubedl_from_txt() {
    : ${1?"Usage: ${FUNCNAME[0]} <txt_file>"}
    youtube-dl -a "$1" --download-archive .downloaded.txt $YOUTUBEDL_PARAMS
  }

  function bh_youtubedl_video480() {
    : ${1?"Usage: ${FUNCNAME[0]} <txt_file>"}
    youtube-dl "$1" -f 'best[height<=480]' $YOUTUBEDL_PARAMS
  }

  function bh_youtubedl_video480_from_txt() {
    : ${1?"Usage: ${FUNCNAME[0]} <txt_file>"}
    youtube-dl -a "$1" -f 'best[height<=480]' $YOUTUBEDL_PARAMS
  }

  function bh_youtubedl_audio() {
    : ${1?"Usage: ${FUNCNAME[0]} <txt_file>"}
    youtube-dl "$1" $YOUTUBEDL_PARAMS -f bestaudio --extract-audio --audio-format mp3 --audio-quality 0 --ignore-errors --embed-thumbnail --output "%(title)s.%(ext)s" --metadata-from-title "%(artist)s - %(title)s" --add-metadata
  }

  function bh_youtubedl_audio_best_from_txt() {
    : ${1?"Usage: ${FUNCNAME[0]} <txt_file>"}
    youtube-dl -a "$1" $YOUTUBEDL_PARAMS -f bestaudio --extract-audio --audio-format mp3 --audio-quality 0 --ignore-errors --embed-thumbnail --output "%(title)s.%(ext)s" --metadata-from-title "%(artist)s - %(title)s" --add-metadata
  }