alias ruby_install='gem install '

function ruby_clean_local() {
    rm -rf ~/.bundle/ ~/.gem/
    rm -rf $GEM_HOME/bundler/ $GEM_HOME/cache/bundler/
    rm -rf .bundle/
    rm -rf vendor/cache/
    rm -rf Gemfile.lock
}
