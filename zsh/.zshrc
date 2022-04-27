export ZSH=$HOME/.oh-my-zsh
ZSH_CUSTOM=$HOME/.zsh_custom
#ZSH_THEME=""
COMPLETION_WAITING_DOTS="true"
plugins=(
  git
  git-extras
  gitignore
  wd
)

source $ZSH/oh-my-zsh.sh
# assume the setup script will symlink the ~/laptop to the correct location
export REQUESTS_CA_BUNDLE=~/.ca-bundle.crt
export AWS_CA_BUNDLE=~/.ca-bundle.crt
export CA_BUNDLE=~/.ca-bundle.crt
export NODE_EXTRA_CA_CERTS=~/.ca-bundle.crt
