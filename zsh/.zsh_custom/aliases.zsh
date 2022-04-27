#!/usr/bin/env zsh

# Homebrew
alias bls='brew list'
alias bo='brew outdated'
alias bcp='brew cleanup && brew prune'
alias bucp='brew upgrade && brew cleanup && brew prune'

alias ..='cd ..'
alias ..2='cd ../..'
alias ..3='cd ../../..'
alias ..4='cd ../../../..'
alias h="cd"
alias c="clear"

# SSH key
alias pubkey='pbcopy < ~/.ssh/id_rsa.pub'

# Reload ZSH
alias reload='source ~/.zshrc'

# Pipe to pretty format XML
alias xml='xmllint --format -'

# Misspellings
alias get='git'
alias gti='git'

# Git
alias clone='git clone'
alias gbls="git for-each-ref --format='%(committerdate) %09 %(authorname) %09 %(refname)' | sort -k5n -k2M -k3n -k4n"
alias gcm='git commit -m'
alias gfa='git fetch --all'
alias gkd='git ksdiff'
alias glc='git log -p --follow -n 1'
alias glod='git pull origin develop'
alias glom='git pull origin master'
alias gpod='git push origin develop'
alias gpom='git push origin master'
alias gs='git status'
alias merge='git merge'
alias pull='git pull'
alias push='git push'

# https://dev.to/chilcutt/smarter-git-checkout-with-fzf-2k5n
# NOTE: fzf must be installed
alias gcof="git for-each-ref --format='%(refname:short)' refs/heads | fzf | xargs git checkout"
alias gcor="git branch -r --sort=-committerdate | fzf | xargs git checkout"
alias gcol="git branch -l --sort=-committerdate | fzf | xargs git checkout"

# Misc
alias ..='cd ..'
alias ..2='cd ../..'
alias ..3='cd ../../..'
alias ..4='cd ../../../..'
# alias ls='grc ls -la'
alias l='exa --long'
alias c="clear"
alias reload="source ~/.bash_profile"

# mvim
if [ -e /Applications/MacVim.app ]
then
  alias mvim=/Applications/MacVim.app/Contents/bin/mvim
fi

# VSCode
alias vsc="code ."
alias vsca="code --add"
alias vscd="code --diff"
alias vscg="code --goto"
alias vscn="code --new-window"
alias vscr="code --reuse-window"
alias vscw="code --wait"
alias vscu="code --user-data-dir"
alias vsced="code --extensions-dir"
alias vscie="code --install-extension"
alias vscue="code --uninstall-extension"
alias vscv="code --verbose"
alias vscl="code --log"
alias vscde="code --disable-extensions"
