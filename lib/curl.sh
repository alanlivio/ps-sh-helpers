# ---------------------------------------
# curl
# ---------------------------------------

function bh_curl_get() {
  curl -i -s -X GET $1
}

function bh_curl_post() {
  curl -i -s -X POST $1
}

function bh_curl_post_json() {
  curl -i -s -X POST $1 --header 'Content-Type: application/json' --header 'Accept: application/json' -d "$2"
}

function bh_curl_fetch_to_dir() {
  curl -O $1 --create-dirs --output-dir $2
}
