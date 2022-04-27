ulimit -n 8192

# Homebrew
if [ -d $HOME/.homebrew ]; then
    HOMEBREW=$HOME/.homebrew
else
    HOMEBREW=/usr/local
fi

export HOMEBREW
export PATH=$HOMEBREW/bin:$PATH
export PATH="$PATH:$HOME/lib:$HOME/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

# Homebbrew
export HOMEBREW_NO_ANALYTICS=1
# ZSH context highlighting and suggestions
source $HOMEBREW/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh
source $HOMEBREW/share/zsh-autosuggestions/zsh-autosuggestions.zsh
export HOMEBREW_CASK_OPTS="--appdir=~/Applications"

# User configuration

# For tab completion
export FIGNORE=".o:~:Application Scripts"

# Java
export JAVA_HOME=$(/usr/libexec/java_home -v 1.8)
export JAVA8_HOME=$JAVA_HOME
export JAVA7_HOME=$JAVA_HOME
export JAVA6_HOME=$JAVA_HOME

# FZF
export FZF_DEFAULT_COMMAND='rg --files --no-ignore --hidden --follow --glob "!.git/*"'
export FZF_CTRL_T_COMMAND="$FZF_DEFAULT_COMMAND"

# Eliminate duplicate path entries
typeset -U PATH
