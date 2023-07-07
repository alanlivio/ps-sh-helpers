function rsync_download_folder(){
  : ${2?"Usage: ${FUNCNAME[0]} <remove_folder> <local_folder>"}
  rsync -avzP $1 $2
}