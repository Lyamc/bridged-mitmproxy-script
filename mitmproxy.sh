#!/bin/bash

# Note
# This will disable NetworkManager and enable systemd-networkd

# There are a few prompts
# Currently, only two bridged interfaces are supported, but that would be easy enough to change. Just need a for loop on the interfaces that are actual real interfaces.

install_prerequisites() {
  echo "Installing prerequisites..."
  sudo apt update && sudo apt install -y \
    openssl net-tools curl tmux iptables iproute2 netplan.io systemd-networkd
}

install_mitmproxy() {
  if ! command -v mitmproxy >/dev/null; then
    echo "Mitmproxy not found, installing the latest version..."
    latest_url=$(curl -s https://api.github.com/repos/mitmproxy/mitmproxy/releases/latest | \
      grep browser_download_url | grep -E 'linux.*(tar\.gz|tar\.xz)' | head -1 | cut -d '"' -f 4)
    if [[ -z $latest_url ]]; then
      echo "Error: Could not fetch the latest mitmproxy release URL."
      exit 1
    fi
    curl -L "$latest_url" -o /tmp/mitmproxy.tar.gz
    sudo tar -xzf /tmp/mitmproxy.tar.gz -C /usr/local/bin --strip-components=1
    rm /tmp/mitmproxy.tar.gz
    echo "Mitmproxy installed successfully."
  else
    echo "Mitmproxy is already installed."
  fi
}

generate_ssl_cert() {
  local cert_path=~/mitmproxy.pem
  if [[ ! -f $cert_path ]]; then
    echo "Generating SSL certificate at $cert_path..."
    openssl req -x509 -newkey rsa:2048 -keyout "$cert_path" -out "$cert_path" -days 365 -nodes \
      -subj "/CN=mitmproxy"
    echo "Certificate generated."
  else
    echo "SSL certificate already exists at $cert_path."
  fi
}

setup_br_netfilter() {
  if ! lsmod | grep -q br_netfilter; then
    echo "br_netfilter module not loaded. Loading and enabling it permanently..."
    echo "br_netfilter" | sudo tee -a /etc/modules >/dev/null
    sudo modprobe br_netfilter
  fi
  if lsmod | grep -q br_netfilter; then
    echo "br_netfilter module is active."
  else
    echo "Failed to load br_netfilter. Exiting."
    exit 1
  fi
}

set_sysctl_settings() {
  echo "Configuring sysctl settings..."
  sudo tee /etc/sysctl.d/99-mitmproxy.conf >/dev/null <<EOF
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-arptables = 1
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
EOF
  sudo sysctl --system
}

handle_network_manager() {
  if systemctl is-active --quiet NetworkManager; then
    echo "Stopping and disabling NetworkManager..."
    sudo systemctl stop NetworkManager
    sudo systemctl disable NetworkManager
  else
    echo "NetworkManager is already stopped and disabled."
  fi
}

get_interfaces() {
echo "Getting interfaces"
# Change these to be the two ethernet interfaces on the computer.
nmcli device status | awk 'NR>1 {printf NR-1 ") "; for (i=1; i<=NF; i++) printf "%s ", $i; print ""}' | column -t
read -p "Enter the number for the first interface: " choice
interface1=$(nmcli device status | awk 'NR=='$((choice+1))' {print $1}')
read -p "Enter the number for the second interface: " choice
interface2=$(nmcli device status | awk 'NR=='$((choice+1))' {print $1}')
echo "Using $interface1 and $interface2"
}

configure_netplan() {
  echo "Configuring netplan for interfaces..."
  sudo rm -f /etc/netplan/*.yaml
  sudo tee /etc/netplan/01-mitmproxy.yaml >/dev/null <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $interface1:
      dhcp4: false
      dhcp6: false
    $interface2:
      dhcp4: false
      dhcp6: false
  bridges:
    br0:
      dhcp4: true
      interfaces:
        - $interface1
        - $interface2
EOF
  sudo netplan apply
}

enable_networkd() {
  echo "Enabling and starting systemd-networkd..."
  sudo systemctl enable systemd-networkd
  sudo systemctl start systemd-networkd
}

wait_for_ip() {
  echo "Waiting for br0 to acquire an IP address..."
  until ip addr show br0 | grep -q 'inet '; do
    sleep 1
  done
  echo "IP address acquired on br0:"
  ip addr show br0 | grep 'inet '
}

prompt_for_ip() {
  while true; do
    read -p "Enter the IPv4 address to sniff traffic: " sniff_ip
    if [[ $sniff_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "Using IP address: $sniff_ip"
      break
    else
      echo "Invalid IP address. Please try again."
    fi
  done
}

configure_iptables() {
  echo "Flushing current iptables rules and setting up new rules..."
  sudo iptables -F
  sudo iptables -t nat -F
  sudo iptables -t nat -A PREROUTING -i br0 -s "$sniff_ip" -p tcp --dport 443 -j REDIRECT --to-port 8080
  echo "IPTables rules applied."
}

run_mitmproxy() {
  echo "Starting mitmproxy in a tmux session..."
  tmux new-session -d -s mitm "mitmproxy --mode transparent --showhost --set block_global=false --certs ~/mitmproxy.pem --set add-upstream-certs-to-client-chain=true --ssl-insecure"
  echo "Mitmproxy is running in tmux session 'mitm'."
}

install_prerequisites
install_mitmproxy
generate_ssl_cert
setup_br_netfilter
set_sysctl_settings
handle_network_manager
get_interfaces
configure_netplan
enable_networkd
wait_for_ip
prompt_for_ip
configure_iptables
run_mitmproxy
