#!/bin/bash

$REPO=https://github.com/tbennett6421/MBP-Setup.git
$U=https://github.com/tbennett6421/MBP-Setup.git/raw/utils.sh?at=refs%2Fheads%2Fmaster


# Sourcing the utils.sh
source <(curl -s $U)

# Check if OSX Command line tools are installed
if ! xcode-select --print-path &> /dev/null; then
  errorMessage "Missing OSX Command Line Tools or Xcode. Install from Self Service."
  exit 1
fi

cd ~
git clone $REPO
cd ~/laptop
./setup.sh
