#!/bin/bash
sudo apt install git-core
git clone https://github.com/alanlivio/bash-helpers.git ~/.bh
    echo "source ~/.bh/rc.sh" >> ~/.bashrc &&\
    source ~/.bashrc