echo " - setting up transparent proxy:"

echo "   - retrieving current ip address"
ip=$(ifconfig | grep "inet " | grep -Fv 127.0.0.1 | awk '{print $2}' | head -n 1)

echo "   - using mitmproxy host: $ip"

echo "   - preparing iptables"
adb shell "su -c '
iptables -t nat -F

# Do not redirect traffic already going to mitmproxy
iptables -t nat -A OUTPUT -p tcp -d $ip --dport 8080 -j RETURN

# Redirect HTTP and HTTPS to mitmproxy
iptables -t nat -A OUTPUT -p tcp --dport 80  -j DNAT --to-destination $ip:8080
iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination $ip:8080

# Fix source NAT
iptables -t nat -A POSTROUTING -p tcp --dport 80  -j MASQUERADE
iptables -t nat -A POSTROUTING -p tcp --dport 443 -j MASQUERADE
'"