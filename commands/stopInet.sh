sudo pkill -f inetsim
sudo dnsmasq --no-daemon \
  --listen-address=10.0.3.1 \
  --bind-interfaces \
  --server=8.8.8.8 \
  --server=1.1.1.1 &
sudo iptables -t nat -D PREROUTING -i eth1 -j REDIRECT
