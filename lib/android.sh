# ---------------------------------------
# android funcs
# ---------------------------------------

function hf_android_start_activity() {
  #adb shell am start -a android.intent.action.MAIN -n com.android.browser/.BrowserActivity
  #adb shell am start -a android.intent.action.MAIN -n org.libsdl.app/org.libsdl.app.SDLActivity
  : ${1?"Usage: ${FUNCNAME[0]} <activity>"}
  adb shell am start -a android.intent.action.MAIN -n "$1"
}

function hf_android_restart_adb() {
  sudo adb kill-server && sudo adb start-server
}

function hf_android_get_ip() {
  adb shell netcfg
  adb shell ifconfig wlan0
}

function hf_android_enable_stdout_stderr_output() {
  adb shell stop
  adb shell setprop log.redirect-stdio true
  adb shell start
}

function hf_android_get_printscreen() {
  adb shell /system/bin/screencap -p /sdcard/screenshot.png
  adb pull /sdcard/screenshot.png screenshot.png
  adb pull /sdcard/screenshot.png screenshot.png
}

function hf_android_list_installed() {
  : ${1?"Usage: ${FUNCNAME[0]} <package>"}
  adb shell pm list packages | grep $1
}

function hf_android_install() {
  : ${1?"Usage: ${FUNCNAME[0]} <package>"}
  adb install $1
}

function hf_android_uninstall() {
  : ${1?"Usage: ${FUNCNAME[0]} <package_in_format_XXX.YYY.ZZZ>"}
  adb uninstall $1
}
