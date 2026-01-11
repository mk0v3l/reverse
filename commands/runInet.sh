sudo inetsim &
sudo dnsmasq --no-daemon --listen-address=10.0.3.1 --bind-interfaces --address=/#/10.0.3.1 &
sudo iptables -t nat -A PREROUTING -i eth1 -j REDIRECT
