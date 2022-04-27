# https://gist.github.com/junegunn/8b572b8d4b5eddd8b85e5f4d40f17236

join-lines() {
  local item
  while read item; do
    echo -n "${(q)item} "
  done
}

# Binds Ctrl+arg to corresponding fzf git function, Ctrl+f maps to _gf() for example.
# If the _gx() functions are ever renamed or you wish to change keybindings,
# then you will need to modify this function, its args, and .inputrc bindings to match.
# To check what a binding is currently mapped to, you can use the bindkey command with one argument
# `bindkey "^g^f"` should return `"^G^F" fzf-gf-widget`
bind-git-helper() {
  local c
  for c in $@; do
    eval "fzf-g$c-widget() { local result=\$(_g$c | join-lines); zle reset-prompt; LBUFFER+=\$result }"
    eval "zle -N fzf-g$c-widget"
    eval "bindkey '^g^$c' fzf-g$c-widget"
  done
}
bind-git-helper f b t r h s
unset -f bind-git-helper
