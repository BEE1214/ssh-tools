#!/bin/bash
set -euo pipefail

# sshm install script
# Builds the project and installs the binary to $HOME/.local/bin
# Optionally installs shell completion

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$HOME/.local/bin"
COMPLETION_DIR="/usr/share/sshm"

BINARY_NAME="sshm"
BINARY_PATH="$INSTALL_DIR/$BINARY_NAME"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info()  { echo -e "${CYAN}==>${NC} $1"; }
ok()    { echo -e "${GREEN}==>${NC} $1"; }
warn()  { echo -e "${YELLOW}!! ${NC} $1"; }
error() { echo -e "${RED}!! ${NC} $1" >&2; }

# --- Checks ---

check_go() {
    if ! command -v go &>/dev/null; then
        error "Go is not installed or not in PATH."
        error "Install from https://go.dev/doc/install"
        exit 1
    fi
}

check_install_dir() {
    if [[ ! -d "$INSTALL_DIR" ]]; then
        info "Creating $INSTALL_DIR"
        mkdir -p "$INSTALL_DIR"
    fi
}

# --- Build ---

build() {
    info "Building $BINARY_NAME..."
    cd "$SCRIPT_DIR"
    go build -o "$BINARY_PATH" ./cmd/sshm/
    ok "Built $BINARY_PATH"
}

# --- Completion ---

SUPPORTED_SHELLS=("bash" "zsh" "fish")

generate_completion() {
    local shell="$1"
    local ext
    case "$shell" in
        bash) ext="sh" ;;
        zsh)  ext="zsh" ;;
        fish) ext="fish" ;;
        *)    ext="$shell" ;;
    esac
    local target="$COMPLETION_DIR/completion.$ext"
    "$BINARY_PATH" completion "$shell" | sudo tee "$target" >/dev/null
    echo "$target"
}

completion_hint() {
    local shell="$1"
    local target="$2"
    case "$shell" in
        bash)
            echo "  Add to ~/.bashrc:"
            echo "    source $target"
            ;;
        zsh)
            echo "  Add to ~/.zshrc:"
            echo "    source $target"
            ;;
        fish)
            echo "  Fish auto-loads from $target if in completions dir."
            echo "  Or add to ~/.config/fish/config.fish:"
            echo "    source $target"
            ;;
    esac
}

install_completions() {
    echo
    info "Shell completion setup"
    echo "  Available shells: ${SUPPORTED_SHELLS[*]}"
    echo "  Select which completions to install (space-separated, or 'all' or 'none'):"
    read -r -p "  > " selection

    if [[ "$selection" == "none" || -z "$selection" ]]; then
        ok "Skipping completion installation."
        return
    fi

    # Need sudo for /usr/share/sshm
    if ! sudo -n true 2>/dev/null; then
        info "Creating $COMPLETION_DIR (requires sudo)"
    fi
    sudo mkdir -p "$COMPLETION_DIR"

    local shells_to_install=()
    if [[ "$selection" == "all" ]]; then
        shells_to_install=("${SUPPORTED_SHELLS[@]}")
    else
        for s in $selection; do
            if [[ " ${SUPPORTED_SHELLS[*]} " == *" $s "* ]]; then
                shells_to_install+=("$s")
            else
                warn "Unknown shell: $s (skipping)"
            fi
        done
    fi

    if [[ ${#shells_to_install[@]} -eq 0 ]]; then
        ok "No completions selected."
        return
    fi

    for shell in "${shells_to_install[@]}"; do
        info "Generating $shell completion..."
        local target
        target=$(generate_completion "$shell")
        ok "Installed: $target"
        completion_hint "$shell" "$target"
    done
}

# --- PATH check ---

check_path() {
    case ":$PATH:" in
        *":$INSTALL_DIR:"*)
            ;;
        *)
            warn "$INSTALL_DIR is not in your PATH."
            echo "  Add to your shell config:"
            echo "    export PATH=\"$INSTALL_DIR:\$PATH\""
            ;;
    esac
}

# --- Main ---

main() {
    echo -e "${CYAN}sshm installer${NC}"
    echo

    check_go
    check_install_dir
    build
    check_path
    install_completions

    echo
    ok "Installation complete."
    echo "  Binary: $BINARY_PATH"
    echo "  Run:    $BINARY_NAME list"
}

main