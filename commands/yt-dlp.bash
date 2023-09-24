ARGS_ALL="--no-warnings --windows-filenames --output %(title)s"
ARGS_BACTH="$AR--download-archive .downloaded.txt --no-playlist"

function yt_dlp_sub_en() {
    : ${1?"Usage: ${FUNCNAME[0]} <url to video>"}
    local url=${1%%&*} # remove all after & (to leave only www.youtube.com/watch?v=...)
    yt-dlp $ARGS_ALL --skip-download --write-sub --sub-langs en "$url"
}

function yt_dlp_audio() {
    : ${1?"Usage: ${FUNCNAME[0]} <url to audio or list>"}
    yt-dlp $ARGS_ALL --extract-audio --audio-format m4a "$1"
}

function yt_dlp_audio_from_txt() {
    : ${1?"Usage: ${FUNCNAME[0]} <url to audio or list>"}
    yt-dlp $ARGS_ALL $ARGS_BACTH --extract-audio --audio-format m4a --batch-file "$1" 
}

function yt_dlp_video_480() {
    : ${1?"Usage: ${FUNCNAME[0]} <url to video or list>"}
    yt-dlp $ARGS_ALL -f 'best[height<=480]' --recode-video mp4 "$1"
}

function yt_dlp_video_480_from_txt() {
    : ${1?"Usage: ${FUNCNAME[0]} <txt_file>"}
    yt-dlp $ARGS_ALL $ARGS_BACTH -f 'best[height<=480]' --recode-video mp4 --batch-file "$1" 
}
