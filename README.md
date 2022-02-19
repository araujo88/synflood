# synflood
SYN flood denial-of-service (DoS) attack coded in C using raw sockets. Generates random spoofed IPs at each new packet.

## Build

`make clean` <br>
`make`

## Usage

`sudo ./synflood <target_ip_address> <payload> <number_of_threads>`
