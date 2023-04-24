fish_add_path "$HOME/usr/bin"

########################
# exa (ls replacement) #
########################
if test -x /usr/bin/exa
    # Common options
    function exa -d 'A modern replacement for ls' -w exa
        command /usr/bin/exa --color auto --color-scale --group-directories-first --level 2 $argv
    end
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
end
