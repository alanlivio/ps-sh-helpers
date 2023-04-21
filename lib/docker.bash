alias docker_prune="docker container prune; docker image prune -a"
function docker_run_at_same_folder(){
  : ${2?"Usage: ${FUNCNAME[0]} <image> <command and args>"}
  local image=$1
  shift 1
  local cmd="$*"
  docker run -v $(pwd):$(pwd) -w $(pwd) -it $image $cmd
}