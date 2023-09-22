function yt_dlp_sub_en() {
    : ${1?"Usage: ${FUNCNAME[0]} <url to video>"}
    local url=${1%%&*} # remove all after & (to leave only www.youtube.com/watch?v=...)
    yt-dlp --write-sub --skip-download --no-playlist --sub-langs en "$url"
}

function yt_dlp_audio() {
    : ${1?"Usage: ${FUNCNAME[0]} <url to audio or list>"}
    yt-dlp --extract-audio --audio-format m4a "$1"
}

function yt_dlp_audio_from_txt() {
    : ${1?"Usage: ${FUNCNAME[0]} <url to audio or list>"}
    yt-dlp --extract-audio --audio-format m4a --batch-file "$1"
}

function yt_dlp_video_480() {
    : ${1?"Usage: ${FUNCNAME[0]} <url to video or list>"}
    yt-dlp -f 'best[height<=480]' --recode-video mp4 "$1"
}

function yt_dlp_video_480_from_txt() {
    : ${1?"Usage: ${FUNCNAME[0]} <txt_file>"}
    yt-dlp -f 'best[height<=480]' --recode-video mp4 --batch-file "$1"
}
