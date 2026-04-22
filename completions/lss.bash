# bash completion for the lss CLI
#
# Install:
#   sudo cp completions/lss.bash /etc/bash_completion.d/lss
#   . /etc/bash_completion.d/lss
#
# Or per-user:
#   cp completions/lss.bash ~/.local/share/bash-completion/completions/lss

_lss() {
    local cur prev words cword
    _init_completion 2>/dev/null || {
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    }

    local commands="audit harden rollback report list help-all"
    local global_opts="-h --help -V --version --json --no-color --license-key"

    # Find the subcommand if any
    local subcmd=""
    local i
    for ((i=1; i < cword; i++)); do
        case "${words[i]}" in
            audit|harden|rollback|report|list|help-all)
                subcmd="${words[i]}"
                break
                ;;
        esac
    done

    # Subcommand-specific options
    case "$subcmd" in
        audit)
            case "$prev" in
                --profile)
                    COMPREPLY=( $(compgen -W "server workstation hardened" -- "$cur") )
                    return
                    ;;
                --control)
                    return  # control IDs are too many to enumerate here
                    ;;
            esac
            COMPREPLY=( $(compgen -W "--profile --control $global_opts" -- "$cur") )
            return
            ;;
        harden)
            COMPREPLY=( $(compgen -W "--confirm --dry-run --control $global_opts" -- "$cur") )
            return
            ;;
        rollback)
            COMPREPLY=( $(compgen -W "--last --run-id --control $global_opts" -- "$cur") )
            return
            ;;
        report)
            case "$prev" in
                -o|--output)
                    _filedir
                    return
                    ;;
            esac
            COMPREPLY=( $(compgen -W "-o --output $global_opts" -- "$cur") )
            return
            ;;
        list|help-all)
            COMPREPLY=( $(compgen -W "$global_opts" -- "$cur") )
            return
            ;;
    esac

    # No subcommand yet — complete commands or global options
    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$global_opts" -- "$cur") )
    else
        COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
    fi
}

complete -F _lss lss
