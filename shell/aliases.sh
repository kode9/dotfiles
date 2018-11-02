# Common aliases for all shells

alias df='df -hT'
alias du='du -ch'
alias https='http --default-scheme=https'
alias mkdir='mkdir -v -p'
alias mod='stat -L -c "%n %F %U(%u) %G(%g) %A(%a)"'
alias mount='mount |column -t'
alias netwatch='watch -d -t netstat -Wltunpe'

# ls / exa
alias exa='exa --color auto --color-scale --group-directories-first --level 2'
alias ls='exa --grid --across'
alias l='exa --long --group --time-style=iso --git'
alias ll='l --grid --across'
alias la='l --all'
alias lla='l --all --grid --across'
alias ltime='l --sort time --time-style=long-iso'
alias lsize='l --sort size'
alias ltype='l --sort extension'
alias lr='l --recurse'
alias ltree='l --tree'
alias lfull='la --all --header -H -@'
