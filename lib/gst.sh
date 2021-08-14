# ---------------------------------------
# gst helpers
# ---------------------------------------

function bh_gst_audio_create_empty() {
  : ${1?"Usage: ${FUNCNAME[0]} [audio_output]"}
  bh_log_func
  gst-launch-1.0 audiotestsrc wave=4 ! audioconvert ! lamemp3enc ! id3v2mux ! filesink location="$1"
}

function bh_gst_side_by_side_test() {
  bh_log_func
  gst-launch-1.0 compositor name=comp sink_1::xpos=640 ! videoconvert ! ximagesink videotestsrc pattern=snow ! "video/x-raw,format=AYUV,width=640,height=480,framerate=(fraction)30/1" ! timeoverlay ! queue2 ! comp. videotestsrc pattern=smpte ! "video/x-raw,format=AYUV,width=640,height=480,framerate=(fraction)10/1" ! timeoverlay ! queue2 ! comp.
}

function bh_gst_side_by_side_args() {
  : ${2?"Usage: ${FUNCNAME[0]} <video1 <video2>"}
  bh_log_func
  gst-launch-1.0 compositor name=comp sink_1::xpos=640 ! ximagesink filesrc location=$1 ! "video/x-raw,format=AYUV,width=640,height=480,framerate=(fraction)30/1" ! decodebin ! videoconvert ! comp. filesrc location=$2 ! "video/x-raw,format=AYUV,width=640,height=480,framerate=(fraction)10/1" ! decodebin ! videoconvert ! comp.
}
