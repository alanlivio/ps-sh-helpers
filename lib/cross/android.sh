# ---------------------------------------
# android
# ---------------------------------------

function bh_android_start_activity() {
  #adb shell am start -a android.intent.action.MAIN -n com.android.browser/.BrowserActivity
  : ${1?"Usage: ${FUNCNAME[0]} <activity>"}
  adb shell am start -a android.intent.action.MAIN -n "$1"
}

function bh_android_get_ip() {
  adb shell netcfg
  adb shell ifconfig wlan0
}

function bh_android_enable_stdout_stderr_output() {
  adb shell stop
  adb shell setprop log.redirect-stdio true
  adb shell start
}

function bh_android_get_printscreen() {
  adb shell /system/bin/screencap -p /sdcard/screenshot.png
  adb pull /sdcard/screenshot.png screenshot.png
}

function bh_android_list_installed() {
  : ${1?"Usage: ${FUNCNAME[0]} <package>"}
  adb shell pm list packages | grep $1
}

function bh_android_install() {
  : ${1?"Usage: ${FUNCNAME[0]} <package>"}
  adb install $1
}

function bh_android_uninstall() {
  : ${1?"Usage: ${FUNCNAME[0]} <package_in_format_XXX.YYY.ZZZ>"}
  adb uninstall $1
}
