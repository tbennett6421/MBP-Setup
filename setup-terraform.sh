#!/usr/bin/env zsh

# Functions
function install_or_upgrade {
    if brew ls --versions "$1" >/dev/null; then
        printf " - $1 already installed skipping\n"
        # HOMEBREW_NO_AUTO_UPDATE=1 brew upgrade "$1"
    else
        HOMEBREW_NO_AUTO_UPDATE=1 brew install "$1"
    fi
}

# Dependencies
brew install tfenv
tfenv install 0.14.11
tfenv use 0.14.11
install_or_upgrade terraform-docs

echo "Terraform is now installed!"
