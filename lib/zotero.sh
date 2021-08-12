# ---------------------------------------
# zotero
# ---------------------------------------

function bh_zotero_sanity() {
  local prefs
  if $IS_LINUX; then
    prefs="$HOME/.zotero/zotero/*.default/prefs.js"
  elif $IS_WINDOWS; then
    prefs="$HOME/AppData/Roaming/Zotero/Zotero/Profiles/*.default/prefs.js"
  fi
  echo 'user_pref("extensions.zotero.automaticSnapshots", false);' >>$prefs
  echo 'user_pref("extensions.zotero.recursiveCollections", true);' >>$prefs
  echo 'user_pref("extensions.zotero.firstRun.skipFirefoxProfileAccessCheck", true);' >>$prefs
  echo 'user_pref("extensions.zotero.attachmentRenameFormatString", "{%t{80}");' >>$prefs
  echo 'user_pref("extensions.zoteroWinWordIntegration.installed", false);' >>$prefs
}

function bh_zotero_onedrive() {
  local prefs
  if $IS_LINUX; then
    prefs="$HOME/.zotero/zotero/*.default/prefs.js"
  elif $IS_WINDOWS; then
    prefs="$HOME/AppData/Roaming/Zotero/Zotero/Profiles/*.default/prefs.js"
  fi
  echo 'user_pref("extensions.zotero.dataDir", "C:\\Users\\${USER}\\OneDrive\\Zotero");' >>$prefs
}
