#!/usr/bin/env zsh

brew analytics off
export HOMEBREW_CASK_OPTS="--appdir=~/Applications"
brew bundle --verbose
brew link curl --force

