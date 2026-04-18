#!/bin/bash

set -e

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/lo-first"
PLIST_FILE="com.lo-first.plist"

detect_os() {
    case "$(uname -s)" in
        Linux*)
            if [ -d /run/systemd/system ]; then
                echo "systemd"
            else
                echo "linux-init"
            fi
            ;;
        Darwin*)
            echo "launchd"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

uninstall_linux() {
    echo "Stopping systemd service..."
    sudo systemctl stop lo-first 2>/dev/null || true
    sudo systemctl disable lo-first 2>/dev/null || true

    echo "Removing systemd service..."
    sudo rm -f /etc/systemd/system/lo-first.service
    sudo systemctl daemon-reload

    echo "Removing binary..."
    sudo rm -f "$INSTALL_DIR/lo-first"

    echo "Removing config..."
    sudo rm -rf "$CONFIG_DIR"

    echo "Uninstall complete!"
}

uninstall_macos() {
    echo "Stopping launchd service..."
    sudo launchctl unload /Library/LaunchDaemons/"$PLIST_FILE" 2>/dev/null || true

    echo "Removing plist..."
    sudo rm -f /Library/LaunchDaemons/"$PLIST_FILE"

    echo "Removing binary..."
    sudo rm -f "$INSTALL_DIR/lo-first"

    echo "Removing config..."
    sudo rm -rf "$CONFIG_DIR"

    echo "Uninstall complete!"
}

uninstall_linux_init() {
    echo "Error: This system uses an init system other than systemd."
    echo "Please manually uninstall according to your init system."
    exit 1
}

OS_TYPE=$(detect_os)

case "$OS_TYPE" in
    systemd)
        uninstall_linux
        ;;
    launchd)
        uninstall_macos
        ;;
    linux-init)
        uninstall_linux_init
        ;;
    *)
        echo "Error: Unsupported operating system"
        exit 1
        ;;
esac