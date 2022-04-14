# ---------------------------------------
# ffmpeg
# ---------------------------------------

function ffmpeg_show_motion_vectors() {
  : ${1?"Usage: ${FUNCNAME[0]} <video>"}
  ffplay -flags2 +export_mvs -vf codecview=mv=pf+bf+bb $1
}

function ffmpeg_add_srt_track() {
  : ${3?"Usage: ${FUNCNAME[0]} <video> <srt> <output>"}
  ffmpeg -i $1 -i $2 -c:v copy -c:a copy -c:s mov_text -metadata:s:s:0 $3
}

function ffmpeg_add_srt_in_picutre() {
  : ${3?"Usage: ${FUNCNAME[0]} <video> <srt> <output>"}
  ffmpeg -i $1 -filter:v subtitles=$2 $3
}

function ffmpeg_create_by_image() {
  : ${1?"Usage: ${FUNCNAME[0]} <image>"}
  ffmpeg -loop_input -i "$1".png -t 5 "$1".mp4
}

function ffmpeg_cut_mp4() {
  : ${3?"Usage: ${FUNCNAME[0]} <video> <begin_time_in_format_00:00:00> <end_time_in_format_00:00:00>"}
  ffmpeg -i $1 -vcodec copy -acodec copy -ss $2 -t $3 -f mp4 cuted-$1
}
