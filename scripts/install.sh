#!/bin/bash

set -e

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/dns-server"
PLIST_FILE="com.dns-server.dns-server.plist"

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

install_linux() {
    SERVICE_FILE="dns-server.service"

    echo "Detected Linux with systemd"

    if [ ! -f "bin/dns-server-linux-amd64" ]; then
        echo "Error: bin/dns-server-linux-amd64 not found. Please build first with 'make linux'"
        exit 1
    fi

    echo "Creating directories..."
    sudo mkdir -p "$CONFIG_DIR"

    echo "Installing binary..."
    sudo cp bin/dns-server-linux-amd64 "$INSTALL_DIR/dns-server"
    sudo chmod +x "$INSTALL_DIR/dns-server"

    echo "Installing config..."
    if [ -f config.yaml ]; then
        sudo cp config.yaml "$CONFIG_DIR/config.yaml"
    fi

    echo "Installing systemd service..."
    sudo cp "$SERVICE_FILE" /etc/systemd/system/
    sudo systemctl daemon-reload

    echo "Installation complete!"
    echo ""
    echo "To enable and start the service:"
    echo "  sudo systemctl enable dns-server"
    echo "  sudo systemctl start dns-server"
    echo ""
    echo "To check status:"
    echo "  sudo systemctl status dns-server"
}

install_macos() {
    echo "Detected macOS with launchd"

    if [ ! -f "bin/dns-server-darwin-arm64" ] && [ ! -f "bin/dns-server-darwin-amd64" ]; then
        echo "Error: No macOS binary found. Please build first with 'make macos'"
        exit 1
    fi

    local macos_binary="bin/dns-server-darwin-arm64"
    if [ ! -f "$macos_binary" ]; then
        macos_binary="bin/dns-server-darwin-amd64"
    fi

    echo "Creating directories..."
    sudo mkdir -p "$CONFIG_DIR"

    echo "Installing binary..."
    sudo cp "$macos_binary" "$INSTALL_DIR/dns-server"
    sudo chmod +x "$INSTALL_DIR/dns-server"

    echo "Installing config..."
    if [ -f config.yaml ]; then
        sudo cp config.yaml "$CONFIG_DIR/config.yaml"
    fi

    echo "Installing launchd plist..."
    sudo cp "$PLIST_FILE" /Library/LaunchDaemons/
    sudo chown root:wheel /Library/LaunchDaemons/"$PLIST_FILE"

    echo "Loading service..."
    sudo launchctl load /Library/LaunchDaemons/"$PLIST_FILE"

    echo "Installation complete!"
    echo ""
    echo "The service has been loaded and will start on next boot."
    echo ""
    echo "To check status:"
    echo "  sudo launchctl list | grep dns-server"
    echo ""
    echo "To stop/start manually:"
    echo "  sudo launchctl stop com.dns-server.dns-server"
    echo "  sudo launchctl start com.dns-server.dns-server"
    echo ""
    echo "To uninstall:"
    echo "  sudo launchctl unload /Library/LaunchDaemons/$PLIST_FILE"
    echo "  sudo rm /Library/LaunchDaemons/$PLIST_FILE"
    echo "  sudo rm $INSTALL_DIR/dns-server"
}

install_linux_init() {
    echo "Error: This system uses an init system other than systemd."
    echo "Please manually configure startup according to your init system."
    exit 1
}

OS_TYPE=$(detect_os)

case "$OS_TYPE" in
    systemd)
        install_linux
        ;;
    launchd)
        install_macos
        ;;
    linux-init)
        install_linux_init
        ;;
    *)
        echo "Error: Unsupported operating system"
        exit 1
        ;;
esac