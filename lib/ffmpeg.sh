# ---------------------------------------
# ffmpeg helpers
# ---------------------------------------
function bh_ffmpeg_show_motion_vectors() {
  : ${1?"Usage: ${FUNCNAME[0]} <video>"}
  bh_log_func
  ffplay -flags2 +export_mvs -vf codecview=mv=pf+bf+bb $1
}

function bh_ffmpeg_add_srt_track() {
  : ${3?"Usage: ${FUNCNAME[0]} <video> <srt> <output>"}
  bh_log_func
  ffmpeg -i $1 -i $2 -c:v copy -c:a copy -c:s mov_text -metadata:s:s:0 $3
}

function bh_ffmpeg_add_srt_in_picutre() {
  : ${3?"Usage: ${FUNCNAME[0]} <video> <srt> <output>"}
  bh_log_func
  ffmpeg -i $1 -filter:v subtitles=$2 $3
}

function bh_ffmpeg_create_by_image() {
  : ${1?"Usage: ${FUNCNAME[0]} <image>"}
  bh_log_func
  ffmpeg -loop_input -i "$1".png -t 5 "$1".mp4
}

function bh_ffmpeg_cut_mp4() {
  : ${3?"Usage: ${FUNCNAME[0]} <video> <begin_time_in_format_00:00:00> <end_time_in_format_00:00:00>"}
  bh_log_func
  ffmpeg -i $1 -vcodec copy -acodec copy -ss $2 -t $3 -f mp4 cuted-$1
}
