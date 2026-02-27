# SPIFFE Workload API Shim

## Go Environment Setup

This project uses Go `1.26.0`. The required version is specified in the `.go-version` file at the root of the repository.

### Prerequisites

Install [goenv](https://github.com/go-nv/goenv) to manage Go versions.

```bash
brew install goenv
```

Add the following to your `~/.zshrc`:

```zsh
export GOENV_ROOT="$HOME/.goenv"
export PATH="$GOENV_ROOT/bin:$PATH"
eval "$(goenv init -)"
```

Reload your shell:

```bash
source ~/.zshrc
```

### Install the required Go version

```bash
goenv install 1.26.0
```

### Verify

From the project root, confirm the correct version is active:

```bash
go version
# go version go1.26.0 darwin/arm64
```

goenv will automatically activate the correct version when you `cd` into this directory, based on the `.go-version` file.
