#!/bin/bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
brew install git
git clone https://github.com/alanlivio/bash-helpers.git ~/.bh
    echo "source ~/.bh/rc.sh" >> ~/.bashrc &&\
    source ~/.bashrc