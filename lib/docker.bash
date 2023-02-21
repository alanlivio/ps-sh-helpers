function docker_images(){
   docker images
}

function docker_open_image_bash(){
  docker exec -it $1 bash
}