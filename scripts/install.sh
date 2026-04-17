#!/bin/bash

set -e

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/dns-server"
SERVICE_FILE="dns-server.service"

echo "Installing dns-server..."

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