#!/usr/bin/env zsh

if [[ "$OSTYPE" != "darwin"* ]]; then
  echo "☢️ This script only works on OS X ️️"
  exit 1
fi

source ./utils.sh
HB_PREFIX=$HOME/.homebrew

FILE_CMD="ln"
FILE_CMD_ARGS="-sf"
while getopts ":hca" OPTION; do
  case "$OPTION" in
    h )
      # help
      echo "Usage:"
      echo "    setup.sh -h                 Show help"
      echo "    setup.sh -c                 Copy setup files to home folder instead of using symlinks"
      exit 0
      ;;
    c )
      # use copy command instead of symlink
      FILE_CMD="cp"
      FILE_CMD_ARGS="-f"
      ;;
    a )
      # run artifactory script
      SHOULD_ARTIFACTORY="Y"
      ;;
    \? )
      echo "Usage: setup.sh [-h] [-c]" #[-a]"
      exit 1
      ;;
  esac
done
shift $((OPTIND -1))

echo ""
  infoMessage " "
  infoMessage "We are about to sprinkle some hotness"
  infoMessage "on your MacBook Pro"
  infoMessage " "
echo ""

# Check if XCode Command line tools are installed
if ! xcode-select --print-path &> /dev/null; then
  errorMessage "Missing XCode Command Line Tools."
  exit 1
fi

name=$(git config --global --includes user.name)
email=$(git config --global --includes user.email)

if [ ! -z "$name" ]; then
  stepComplete "Git name configured as: $name"
else
  question "What is your full name?"
  read name
  git config --global user.name "${name}"
fi

if [ ! -z "$email" ]; then
  stepComplete "Git email configured as: $email"
else
  question "What is your email?"
  read email
  git config --global user.email "${email}"
fi

reset

# git
git config --global url."https://".insteadOf git://
git config --global color.ui true
stepComplete "Git Initialized"

# /usr/local locked down so place everything in ~/.homebrew
if ! command -v brew >/dev/null; then
  step "Installing Homebrew"
  echo ""
  mkdir -p $HB_PREFIX && curl -L https://github.com/Homebrew/brew/tarball/master | tar xz --strip 1 -C $HB_PREFIX
  export PATH=$PATH:$HB_PREFIX/bin:$HB_PREFIX/sbin
  echo ""
  stepComplete "Homebrew Installed"
else
  step "Updating Homebrew"
  brew update --verbose
  stepComplete "Homebrew Updated"
fi

step "Installing Homebrew Formulas"
./brew.sh
stepComplete "Homebrew Formulas Installed"

# Create directory for user symlinks
if [ ! -d "$HOME/bin" ]; then
  mkdir -p $HOME/bin
  stepComplete "Created ${HOME}/bin"
fi


echo $VSCODE_BIN_PATH
if [ -z "$VSCODE_BIN_PATH" ]; then
  VSCODE_BIN_PATH=/Applications/Visual\ Studio\ Code.app/Contents/Resources/app/bin/code
fi
echo $VSCODE_BIN_PATH

if [ -f "$VSCODE_BIN_PATH" ]; then
  step "Installing Visual Studio Code plugins"
  ln -sf  "$VSCODE_BIN_PATH" ~/bin/code
  stepComplete "Created symlink for Visual Studio Code"
fi

# step "Configuring macos"
# if ! [ -f ~/.macos ]; then
#   $FILE_CMD $FILE_CMD_ARGS "$(pwd)/macos/.macos" "$HOME/.macos"
# fi
# stepComplete "Configured macos"

echo ""
  infoMessage " "
  infoMessage "Now run the following optional scripts:"
  infoMessage " "
echo ""
statement "setup-terraform.sh - Setup Terraform"
statement "setup-vscode.sh - Setup Visual Studio Code plugins"
statement "setup-zsh.sh - Setup ZSH, oh-my-fish and starship theme"
echo ""
echo -e "$bold ✨ 💥 DONE! PLEASE RELOAD YOUR SHELL 💥 ✨ $bold"
echo ""
