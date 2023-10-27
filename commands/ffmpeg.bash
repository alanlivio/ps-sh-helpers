function ffmpeg_cut_mp4() {
    : ${3?"Usage: ${FUNCNAME[0]} <video> <begin_time_in_format_00:00:00> <end_time_in_format_00:00:00>"}
    ffmpeg -i $1 -vcodec copy -acodec copy -ss $2 -t $3 -f mp4 cuted-$1
}

function ffmpeg_convert_to_mp4_768x432(){
    : ${1?"Usage: ${FUNCNAME[0]} <video>"}
    ffmpeg -i $1  -vf scale=768:-1 -c:v libx264 -c:a aac "${1%.*}.mp4"
}

function ffmpeg_extract_audio_mp4() {
    : ${1?"Usage: ${FUNCNAME[0]} <video>"}
    ffmpeg -i "$1" -vn -acodec copy "${1%.*}.m4a"
}

function ffmpeg_show_motion_vectors() {
    : ${1?"Usage: ${FUNCNAME[0]} <video>"}
    ffplay -flags2 +export_mvs -vf codecview=mv=pf+bf+bb $1
}

function ffmpeg_images_merge_to_mp4() {
    : ${1?"Usage: ${FUNCNAME[0]} <image>"}
    ffmpeg -loop_input -i "$1".png -t 5 "$1".mp4
}

function ffmpeg_mp4_files_merge() {
    : ${1?"Usage: ${FUNCNAME[0]} <file1> ... "}
    ffmpeg -f concat -safe 0 -i <(for f in "$@"; do echo "file '$PWD/$f'"; done) -c copy output.mp4
}
