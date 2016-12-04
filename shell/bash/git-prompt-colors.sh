#!/usr/bin/env bash
#
# ~/.git-prompt-colors.sh
#
# Theme for bash-git-prompt (https://github.com/magicmonty/bash-git-prompt).

# These are global because they are used in the callback
_abz_beg="\["
_abz_end="\]"
_abz_reset="${_abz_beg}$(tput sgr0)${_abz_end}"
_abz_orange="${_abz_beg}$(tput setaf 180)${_abz_end}"

# Truncates $PWD depending on window width. This is a modification of
# `gp_truncate_pwd` because I want less characters but there is no way to
# customize it.
_abz_pwd() {
    local -r tilde="~"
    local -r pwdmaxlen=$((${COLUMNS:-80}/4))
    local newPWD="${PWD/#${HOME}/${tilde}}"
    [ ${#newPWD} -gt $pwdmaxlen ] && newPWD="∞${newPWD:2-$pwdmaxlen}"
    echo -n "${newPWD}"
}

prompt_callback() {
    echo -n "${_abz_orange}[$(_abz_pwd)]${_abz_reset}"
}

override_git_prompt_colors() {
    local -r _color_blue="${_abz_beg}$(tput setaf 111)${_abz_end}"
    local -r _color_cyan="${_abz_beg}$(tput setaf 116)${_abz_end}"
    local -r _color_green="${_abz_beg}$(tput setaf 157)${_abz_end}"
    local -r _color_pink="${_abz_beg}$(tput setaf 181)${_abz_end}"
    local -r _color_red="${_abz_beg}$(tput setaf 174)${_abz_end}"
    local -r _color_yellow="${_abz_beg}$(tput setaf 187)${_abz_end}"

    local -r _user="\u"
    local -r _host="\h"

    GIT_PROMPT_THEME_NAME="Pluc"        # Name of this theme
    GIT_PROMPT_ONLY_IN_REPO=1             # Display git promp only when in a repo
    GIT_PROMPT_FETCH_REMOTE_STATUS=0      # Do not fetch remotes
    unset -v GIT_PROMPT_SHOW_UPSTREAM     # Do not show upstream branches
    GIT_PROMPT_SHOW_UNTRACKED_FILES=no    # {no, normal, all}
    GIT_PROMPT_SHOW_CHANGED_FILES_COUNT=1 # Show number of modified files
    GIT_PROMPT_IGNORE_STASH=1             # Dont show stash info

    GIT_PROMPT_COMMAND_OK="${_color_green}√" # When last command succeed
    GIT_PROMPT_COMMAND_FAIL="${_color_red}✘" # When last command failed
    GIT_PROMPT_START_USER="${_color_blue}${_user}${_color_yellow}@${_color_pink}${_host} "
    GIT_PROMPT_END_USER=" _LAST_COMMAND_INDICATOR_ ${_color_yellow}"
    GIT_PROMPT_START_ROOT="${_color_red}${_user}${_color_yellow}@${_color_pink}${_host} "
    GIT_PROMPT_END_ROOT=${GIT_PROMPT_END_USER}
    GIT_PROMPT_PREFIX="("
    GIT_PROMPT_SUFFIX=")"
    GIT_PROMPT_SEPARATOR=""
    GIT_PROMPT_BRANCH="${_color_blue}"     # Current branch
    GIT_PROMPT_REMOTE=" "                  # Remote branch
    GIT_PROMPT_STAGED="${_color_green}●"   # Staged files
    GIT_PROMPT_CHANGED="${_abz_orange}◐"   # Modified files
    GIT_PROMPT_CONFLICTS="${_color_red}◌"  # Conflicting files
    GIT_PROMPT_UNTRACKED="${_color_cyan}○" # Untracked files
    GIT_PROMPT_STASHED=""                  # Number of stashes
    GIT_PROMPT_CLEAN=""                    # When everything is clean

    ## Please do not add colors to these symbols
    GIT_PROMPT_SYMBOLS_AHEAD="▲"             # Symbol for "n versions ahead of origin"
    GIT_PROMPT_SYMBOLS_BEHIND="▼"            # Symbol for "n versions behind of origin"
    GIT_PROMPT_SYMBOLS_PREHASH=""            # Symbol before hash if no name
    GIT_PROMPT_SYMBOLS_NO_REMOTE_TRACKING="" # Symbol after the branch if not tracked
}

reload_git_prompt_colors "Pluc"

unset -f override_git_prompt_colors

# some unicode characters: ☑☒ √✘ ↑↓ ⇑⇩ ⬆⬇ ▲▼ △▽ ⊕ ⊖ ⊗ ⊘ ◉ ○ ◌ ◍ ◎ ● ◐ ◑ ◒ ◓ ◔ ◕
# ◖ ◗ ■ □ ▢ ▣ ▪ ▫ ⌀ ✛ ✠ ✦ ✧ ✩ ✪ ✫ ✬ ✭ ✮ ✯ ✰ ✱ ✲ ✳ ✴ ✵ ✶ ✷ ✸ ✹ ✺ ❍ ☠ ☢

# Zenburn colors
# 16 #000000
# 16 #2B2B2B
# 16 #383838
# 16 #3F3F3F
# 16 #494949
# 23 #366060
# 59 #4F4F4F
# 59 #5F5F5F
# 59 #656555
# 59 #6F6F6F
# 60 #4C7073
# 65 #5F7F5F
# 66 #5C888B
# 73 #6CA0A3
# 95 #8C5353
# 108 #7F9F7F
# 108 #8FB28F
# 109 #7CB8BB
# 111 #94BFF3
# 116 #8CD0D3
# 116 #93E0E3
# 131 #9C6363
# 138 #AC7373
# 138 #BC8383
# 151 #9FC59F
# 151 #AFD8AF
# 157 #BFEBBF
# 174 #CC9393
# 176 #DC8CC3
# 180 #D0BF8F
# 180 #DFAF8F
# 181 #DCA3A3
# 187 #E0CF9F
# 188 #DCDCCC
# 223 #F0DFAF
# 231 #FFFFEF
