#!/bin/bash

echo "Starting DNS server..."
sudo ./dns 

echo "Restarting systemd-resolved..."
sudo systemctl restart systemd-resolved
