alias ruby_install='gem install '

function ruby_clean_local() {
    rm -rf ~/.bundle/ ~/.gem/
    rm -rf $GEM_HOME/bundler/ $GEM_HOME/cache/bundler/
    rm -rf .bundle/
    rm -rf vendor/cache/
    rm -rf Gemfile.lock
}

function ruby_jekyll_install_essentials() {
    # dev used
    sudo apt install zlib1g-dev build-essential libssl-dev libreadline-dev libyaml-dev libxml2-dev libxslt1-dev libcurl4-openssl-dev libffi-dev imagemagick
    # main
    sudo apt install ruby-dev ruby-rubygems ruby-bundler
}

function ruby_jekyll_serve() {
    bundle install
    bundle exec jekyll serve --watch
}
