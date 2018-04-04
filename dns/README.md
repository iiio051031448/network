# smart DNS

## 再路由器上对53端口进行转发。

iptables -t nat -I PREROUTING -p udp --dport 53 -j DNAT --to-destination 10.2.10.46:8898
