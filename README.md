shellshockUAScanner
Scan CIDR networks for the Shellshock vulnerability in the HTTP Useragent.

Vulnerable web servers will ping the host with 5 ICMP packets to validate exploitability during a penetration test.

Usage:
./shellshockUAScanner.py -r (CIDR range) -t (number of threads *default is 16) -i (interface *default is eth0)