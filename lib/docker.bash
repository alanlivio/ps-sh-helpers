# ---------------------------------------
# docker
# ---------------------------------------

function docker_service_start() {
  sudo usermod -aG docker $USER
  sudo service docker start
}