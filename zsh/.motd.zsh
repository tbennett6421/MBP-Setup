export COWPATH="$HOME/.cows/"
if [ "$(command -v fortune)" ] ; then
    if [ "$(command -v cowsay)" ] ; then
        if [ "$(command -v lolcat)" ] ; then
            fortune -s -n 100 | cowsay -f $(ls "$COWPATH" | gshuf -n1) | lolcat
        else
            fortune -s -n 100 | cowsay -f $(ls "$COWPATH" | gshuf -n1)
        fi
    else
        fortune -s -n 100
    fi
fi
