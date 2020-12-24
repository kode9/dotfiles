# Common aliases for all shells

alias df='df -hT'
alias du='du -ch'
alias https='http --default-scheme=https'
alias mkdir='mkdir -v -p'
alias mod='stat -L -c "%n %F %U(%u) %G(%g) %A(%a)"'
alias mounted='mount |column -t'
alias netwatch='watch -d -t netstat -Wltunpe'

########################
# exa (ls replacement) #
########################
if [ -x /usr/bin/exa ]; then
  # Common options
  alias exa='/usr/bin/exa --color auto --color-scale --group-directories-first --level 2'
  # Column
  alias l='exa --long --group --time-style=iso --git'
  # Like default ls
  alias lc='exa --grid --across'
  # Grid
  alias ll='l --grid --across'
  # Column, hidden files
  alias la='l --all'
  # Grid, hidden files
  alias lla='l --all --grid --across'
  # Column, sorted by time
  alias lti='l --sort time --time-style=long-iso'
  # Column, sorted by size
  alias lsi='l --sort size'
  # Column, grouped by type
  alias lty='l --sort extension'
  # Column, recursive
  alias lre='l --recurse'
  # Tree
  alias ltr='l --tree'
  # Column, detailed informations
  alias lfu='la --all --header -H -@'
fi
