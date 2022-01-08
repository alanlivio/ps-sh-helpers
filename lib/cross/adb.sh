# ---------------------------------------
# adb
# ---------------------------------------

function bh_adb_start_activity() {
  #adb shell am start -a android.intent.action.MAIN -n com.android.browser/.BrowserActivity
  : ${1?"Usage: ${FUNCNAME[0]} <activity>"}
  adb shell am start -a android.intent.action.MAIN -n "$1"
}

function bh_adb_reinstall_providers() {
  adb shell pm install -r --user 0 /system/priv-app/CalendarProvider/CalendarProvider.apk
  adb shell pm install -r --user 0 /system/priv-app/ContactsProvider/ContactsProvider.apk
  adb shell pm install -r --user 0 /system/priv-app/DownloadProvider/DownloadProvider.apk
  adb shell pm install -r --user 0 /system/priv-app/SettingsProvider/SettingsProvider.apk
  adb shell pm install -r --user 0 /system/priv-app/TelephonyProvider/TelephonyProvider.apk
  adb shell pm install -r --user 0 /system/priv-app/ExternalStorageProvider/ExternalStorageProvider.apk
}

function bh_adb_get_ip() {
  adb shell netcfg
  adb shell ifconfig wlan0
}

function bh_adb_enable_stdout_stderr_output() {
  adb shell stop
  adb shell setprop log.redirect-stdio true
  adb shell start
}

function bh_adb_get_printscreen() {
  adb shell /system/bin/screencap -p /sdcard/screenshot.png
  adb pull /sdcard/screenshot.png screenshot.png
}

function bh_adb_list_installed() {
  adb shell pm list packages
}

function bh_adb_ps() {
  adb shell ps
}

function bh_adb_list_running() {
  adb shell ps | grep ^u | awk '{print $9}'
}

function bh_adb_install() {
  : ${1?"Usage: ${FUNCNAME[0]} <package>"}
  adb shell pm install -k --user 0$1
}

function bh_adb_kill() {
  : ${1?"Usage: ${FUNCNAME[0]} <package>"}
  adb shell am kill $1
}

function bh_adb_get_foreground_package() {
  adb shell dumpsys activity recents | grep 'Recent #0' | cut -d= -f2 | sed 's| .*||' | cut -d '/' -f1
}

function bh_adb_uninstall() {
  : ${1?"Usage: ${FUNCNAME[0]} <package_in_format_XXX.YYY.ZZZ>"}
  adb shell pm uninstall -k --user 0 $1
}
