#!/usr/bin/env zsh

source ./utils.sh

echo ""
  infoMessage " "
  infoMessage "We are about to install a superior shell"
  infoMessage "on your MacBook Pro"
  infoMessage " "
echo ""

if command -v brew >/dev/null; then
  step "Installing ZSH"
  brew upgrade
  brew install zsh
  brew install zsh-completions
  brew install zsh-syntax-highlighting
  brew install zsh-autosuggestions
  stepComplete "ZSH files installed from Homebrew"
else
  errorMessage "Homebrew not installed. Please run ./setup.sh"
  exit 1
fi

if ! [ -d "$HOME/.oh-my-zsh" ]; then
  step "Installing Oh My Zsh"
  sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"
fi
stepComplete "Oh My Zsh installed"

step "Configuring ZSH"
# mv -f $HOME/.zshrc $HOME/.zshrc.oh-my-zsh
# ln -fsv $(pwd)/zsh/.zshrc $HOME
# ln -fsv $(pwd)/zsh/.zsh_custom $HOME

# fzf git keybindings
if [[ ! -f $HOME/.inputrc ]]; then
    cp $(pwd)/macos/.inputrc $HOME/.inputrc
fi
stepComplete "Configured ZSH"

echo ""
  infoMessage " "
  infoMessage "Complete"
  infoMessage "Recommend you set your terminal to use ZSH"
  infoMessage " "
echo ""


