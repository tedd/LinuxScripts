Simple firewall script for updating UFW. Its purpose is to resolve hostnames to IP-addresses and update UFW ruleset accordingly.
Add script to crontab, running every hour or so.

firewall.rules has format:
host:proto where host can be multiple coma separated, and proto can be multiple proto:port (i.e. tcp:22,udp:53)
mypc.dyndns.com:tcp:22,tcp:80

Everything after # is ignored.
