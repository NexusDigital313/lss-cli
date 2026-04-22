# Shell completions for lss

## bash

```sh
sudo cp lss.bash /etc/bash_completion.d/lss
# new shell, or:
. /etc/bash_completion.d/lss
```

Per-user (no sudo):

```sh
mkdir -p ~/.local/share/bash-completion/completions
cp lss.bash ~/.local/share/bash-completion/completions/lss
```

## zsh

```sh
sudo cp _lss /usr/share/zsh/site-functions/_lss
# new shell, or:
compinit
```

Per-user:

```sh
mkdir -p ~/.zsh/completions
cp _lss ~/.zsh/completions/_lss
# add this to ~/.zshrc if it isn't already:
#   fpath=(~/.zsh/completions $fpath)
#   autoload -Uz compinit && compinit
```
