#!/bin/bash

set -e

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/dns-server"

echo "Uninstalling dns-server..."

echo "Stopping service..."
sudo systemctl stop dns-server 2>/dev/null || true
sudo systemctl disable dns-server 2>/dev/null || true

echo "Removing systemd service..."
sudo rm -f /etc/systemd/system/dns-server.service
sudo systemctl daemon-reload

echo "Removing binary..."
sudo rm -f "$INSTALL_DIR/dns-server"

echo "Removing config..."
sudo rm -rf "$CONFIG_DIR"

echo "Uninstall complete!"