#!/bin/bash

# Остановка и отключение systemd-resolved
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved

# Удаление старого resolv.conf и создание нового
sudo rm /etc/resolv.conf
sudo cat > /etc/resolv.conf << EOL
nameserver 8.8.8.8
nameserver 8.8.4.4
EOL

# Установка необходимых пакетов
sudo apt update
sudo apt install -y curl network-manager iptables-persistent rfkill dnsmasq

# Остановка существующих соединений
sudo systemctl stop dnsmasq
sudo nmcli con down "wifi-hotspot" 2>/dev/null
sudo nmcli con delete "wifi-hotspot" 2>/dev/null

# Установка XRay
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Создание конфигурации XRay
sudo cat > /usr/local/etc/xray/config.json << 'EOL'
{
  "inbounds": [{
    "port": 1080,
    "protocol": "socks",
    "settings": {
      "auth": "noauth",
      "udp": true
    },
    "sniffing": {
      "enabled": true,
      "destOverride": ["http", "tls"]
    }
  }],
  "outbounds": [{
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "62.60.154.119",
        "port": 444,
        "users": [{
          "id": "81f2b137-c06d-4ee5-b63d-e0b15cab1351",
          "flow": "xtls-rprx-vision",
          "encryption":"none"
        }]
      }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "serverName": "www.microsoft.com",
        "fingerprint": "chrome",
        "publicKey": "qYuTAEB89hRb8beRXwBfbAimNcxWincGBlRGyHAueiI",
        "shortId": "12345678",
        "spiderX": ""
      }
    }
  }]
}
EOL

# Настройка прав доступа для XRay
sudo chown -R nobody:nogroup /usr/local/etc/xray/
sudo chmod 644 /usr/local/etc/xray/config.json

# Настройка автозапуска XRay
sudo systemctl enable xray
sudo systemctl restart xray

# Настройка NetworkManager для использования dnsmasq
sudo cat > /etc/NetworkManager/conf.d/dns.conf << EOL
[main]
dns=none
EOL

# Настройка dnsmasq
sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.orig
sudo cat > /etc/dnsmasq.conf << EOL
interface=wlan0
bind-interfaces
domain-needed
bogus-priv
dhcp-range=192.168.4.2,192.168.4.100,255.255.255.0,24h
dhcp-option=option:router,192.168.4.1
dhcp-option=option:dns-server,8.8.8.8,8.8.4.4
server=8.8.8.8
server=8.8.4.4
EOL

# Разблокировка WiFi
sudo rfkill unblock wifi
sudo nmcli radio wifi on

# Создание точки доступа WiFi с фиксированным IP
sudo nmcli con add \
    type wifi \
    ifname wlan0 \
    con-name "wifi-hotspot" \
    autoconnect yes \
    ssid "Tp-Link 24-251-26" \
    mode ap \
    ipv4.method manual \
    ipv4.addresses "192.168.4.1/24" \
    ipv4.never-default true \
    wifi-sec.key-mgmt wpa-psk \
    wifi-sec.proto rsn \
    wifi-sec.pairwise ccmp \
    wifi-sec.group ccmp \
    wifi-sec.psk "Romdik123" \
    802-11-wireless.band bg

# Включение IP forwarding
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-sysctl.conf
sudo sysctl -p /etc/sysctl.d/99-sysctl.conf

# Очистка существующих правил iptables
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -t mangle -F
sudo iptables -X
sudo iptables -t nat -X
sudo iptables -t mangle -X

# Установка базовых правил
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT

# Разрешаем локальные соединения
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# Разрешаем SSH и установленные соединения
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Разрешаем порт XRay
sudo iptables -A INPUT -p tcp --dport 1080 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 1080 -j ACCEPT

# Настройка NAT для WiFi клиентов
sudo iptables -t nat -A POSTROUTING -s 192.168.4.0/24 ! -d 192.168.4.0/24 -j MASQUERADE

# Настройка перенаправления через прокси
sudo iptables -t nat -N REDSOCKS
sudo iptables -t nat -A REDSOCKS -d 0.0.0.0/8 -j RETURN
sudo iptables -t nat -A REDSOCKS -d 127.0.0.0/8 -j RETURN
sudo iptables -t nat -A REDSOCKS -d 169.254.0.0/16 -j RETURN
sudo iptables -t nat -A REDSOCKS -d 172.16.0.0/12 -j RETURN
sudo iptables -t nat -A REDSOCKS -d 192.168.0.0/16 -j RETURN
sudo iptables -t nat -A REDSOCKS -d 224.0.0.0/4 -j RETURN
sudo iptables -t nat -A REDSOCKS -d 240.0.0.0/4 -j RETURN
sudo iptables -t nat -A REDSOCKS -p tcp -j REDIRECT --to-ports 1080

# Применяем REDSOCKS к трафику от WiFi клиентов
sudo iptables -t nat -A PREROUTING -s 192.168.4.0/24 -p tcp -j REDSOCKS

# Разрешаем DNS запросы
sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 53 -j ACCEPT
sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# Сохранение правил iptables
sudo netfilter-persistent save

# Перезапуск сервисов
sudo systemctl restart NetworkManager
sudo systemctl restart dnsmasq
sudo systemctl restart xray

# Создание скрипта автозапуска
sudo cat > /etc/systemd/system/vpn-router.service << EOL
[Unit]
Description=VPN Router Setup
After=network.target NetworkManager.service
Wants=NetworkManager.service

[Service]
Type=oneshot
RemainAfterExit=yes
Environment="ALL_PROXY=socks5://127.0.0.1:1080"
ExecStart=/bin/true

[Install]
WantedBy=multi-user.target
EOL

# Включение автозапуска
sudo systemctl enable vpn-router.service
sudo systemctl enable dnsmasq

# Активация точки доступа
sudo nmcli con up "wifi-hotspot"

# Создание скрипта для проверки статуса
sudo cat > /usr/local/bin/check-vpn-status << EOL
#!/bin/bash
echo "=== Network Manager Status ==="
systemctl status NetworkManager | grep Active
echo -e "\n=== WiFi Hotspot Status ==="
nmcli con show "wifi-hotspot" | grep -E "GENERAL.STATE|IP4.ADDRESS"
echo -e "\n=== XRay Status ==="
systemctl status xray | grep Active
echo -e "\n=== DNSMasq Status ==="
systemctl status dnsmasq | grep Active
echo -e "\n=== Connected Clients ==="
arp -a | grep wlan0
echo -e "\n=== DNS Settings ==="
cat /etc/resolv.conf
echo -e "\n=== XRay Port Status ==="
netstat -tulpn | grep 1080
echo -e "\n=== IPTables Rules ==="
sudo iptables -t nat -L REDSOCKS
EOL

sudo chmod +x /usr/local/bin/check-vpn-status

echo "Установка завершена. Перезагрузите Raspberry Pi командой: sudo reboot"
echo "После перезагрузки используйте команду 'check-vpn-status' для проверки состояния сервисов"
