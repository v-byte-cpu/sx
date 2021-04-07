# sx

[![Build Status](https://cloud.drone.io/api/badges/v-byte-cpu/sx/status.svg)](https://cloud.drone.io/v-byte-cpu/sx)
[![GoReportCard Status](https://goreportcard.com/badge/github.com/v-byte-cpu/sx)](https://goreportcard.com/report/github.com/v-byte-cpu/sx)

**sx** is the command-line network scanner designed to follow the UNIX philosophy.

The goal of this project is to create the fastest network scanner with clean and simple code.

## Features

  * **ARP scan**: Scan your local networks to detect live devices
  * **TCP SYN scan**: Traditional half-open scan to find open TCP ports
  * **TCP FIN / NULL / Xmas scans**: Scan techniques to bypass some firewall rules
  * **Custom TCP scans with any TCP flags**: Send whatever exotic packets you want and get a result with all the TCP flags set in the reply packet
  * **UDP scan**: Scan UDP ports and get full ICMP replies to detect open ports or firewall rules
  * **SOCKS5 scan**: Detect live SOCKS5 proxies by scanning ip range or list of ip/port pairs from a file
  * **Docker scan**: Detect open Docker daemons listening on TCP ports and get information about the docker node
  * **Elasticsearch scan**: Detect open Elasticsearch nodes and pull out cluster information with all index names
  * **JSON output support**: sx is designed specifically for convenient automatic processing of results

## Build from source

Requirements:

  * [Go 1.15 or newer](https://golang.org/dl/)
  * [libpcap](https://www.tcpdump.org/) (already installed if you use **wireshark**)

From the root of the source tree, run:

```
go build
```

## Quick Start

Here's a quick examples showing how you can scan networks with `sx`.

### ARP scan

Scan your local network and display the IP address, MAC address and associated hardware vendor of connected devices:

```
./sx arp 192.168.0.1/24
```

sample output:

```
192.168.0.1          b0:be:76:40:05:8d    TP-LINK TECHNOLOGIES CO.,LTD.
192.168.0.111        80:c5:f2:0b:02:e3    AzureWave Technology Inc.
192.168.0.171        88:53:95:2d:3c:af    Apple, Inc.
```

with JSON output:

```
./sx arp --json 192.168.0.1/24
```

sample output:

```
{"ip":"192.168.0.1","mac":"b0:be:76:40:05:8d","vendor":"TP-LINK TECHNOLOGIES CO.,LTD."}
{"ip":"192.168.0.111","mac":"80:c5:f2:0b:02:e3","vendor":"AzureWave Technology Inc."}
{"ip":"192.168.0.171","mac":"88:53:95:2d:3c:af","vendor":"Apple, Inc."}
```

wait 5 seconds before exiting to receive delayed reply packets, by default `sx` waits 300 milliseconds:

```
./sx arp --exit-delay 5s 192.168.0.1/24
```

Live scan mode that rescans network every 10 seconds:

```
./sx arp 192.168.0.1/24 --live 10s
```

### TCP scan

Unlike nmap and other scanners that implicitly perform ARP requests to resolve IP addresses to MAC addresses before the actual scan, `sx` explicitly uses the **ARP cache** concept. ARP cache file is a simple text file containing JSON string on each line ([JSONL](https://jsonlines.org/) file), which has the same JSON fields as the ARP scan JSON output described above. Scans of higher-level protocols like TCP and UDP read the ARP cache file from the stdin and then start the actual scan.

This not only simplifies the design of the program, but also speeds up the scanning process, since it is not necessary to perform an ARP scan every time.

Let's assume that the actual ARP cache is in the `arp.cache` file. We can create it manually
or use ARP scan as shown below:

```
./sx arp 192.168.0.1/24 --json | tee arp.cache
```

Once we have the ARP cache file, we can run scans of higher-level protocols like TCP SYN scan:

```
cat arp.cache | ./sx tcp -p 1-65535 192.168.0.171
```

sample output:

```
192.168.0.171        22
192.168.0.171        443
```

In this case we find out that ports 22 and 443 are open.

scan with JSON output:

```
cat arp.cache | ./sx tcp  --json -p 1-65535 192.168.0.171
```

sample output:

```
{"scan":"tcpsyn","ip":"192.168.0.171","port":22}
{"scan":"tcpsyn","ip":"192.168.0.171","port":443}
```

scan multiple port ranges:

```
cat arp.cache | ./sx tcp -p 1-23,25-443 192.168.0.171
```

or individual ports:

```
cat arp.cache | ./sx tcp -p 22,443 192.168.0.171
```

It is possible to specify the ARP cache file using the `-a` or `--arp-cache` options:

```
./sx tcp -a arp.cache -p 22,443 192.168.0.171
```

or stdin redirect:

```
./sx tcp -p 22,443 192.168.0.171 < arp.cache
```

You can also use the `tcp syn` subcommand instead of the `tcp`:

```
cat arp.cache | ./sx tcp syn -p 22 192.168.0.171
```

`tcp` subcomand is just a shorthand for `tcp syn` subcommand unless `--flags` option is passed, see below.

### TCP FIN scan

Most network scanners try to interpret results of the scan. For instance they say "this port is closed" instead of "I received a RST". Sometimes they are right. Sometimes not. It's easier for beginners, but when you know what you're doing, you keep on trying to deduce what really happened from the program's interpretation, especially for more advanced scan techniques. 

`sx` tries to overcome those problems. It returns information about all reply packets for TCP FIN, NULL, Xmas and custom TCP scans. The information contains IP address, TCP port and all TCP flags set in the reply packet.

TCP FIN scan and its other variations (NULL and Xmas) exploit RFC793 Section 3.9:

>  SEGMENT ARRIVES
>
>    If the state is CLOSED (i.e., TCB does not exist) then
>
>      all data in the incoming segment is discarded.  An incoming
>      segment containing a RST is discarded.  An incoming segment not
>      containing a RST causes a RST to be sent in response.  The
>      acknowledgment and sequence field values are selected to make the
>      reset sequence acceptable to the TCP that sent the offending
>      segment.

so closed port should return packet with RST flag.

This section also states that:

> If the state is LISTEN then
>
>   ...
>
>   Any other control or text-bearing segment (not containing SYN)
>   must have an ACK and thus would be discarded by the ACK
>   processing.  An incoming RST segment could not be valid, since
>   it could not have been sent in response to anything sent by this
>   incarnation of the connection.  So you are unlikely to get here,
>   but if you do, drop the segment, and return.

the main phrase here: **drop the segment**, and return. So an open port on most operating systems
will drop the TCP packet containing any flags except SYN,ACK and RST.


Let's scan some closed port with TCP FIN scan:

```
cat arp.cache | ./sx tcp fin --json -p 23 192.168.0.171
```

sample output:

```
{"scan":"tcpfin","ip":"192.168.0.171","port":23,"flags":"ar"}
```

`flags` field contains all TCP flags in the reply packet, where each letter represents one of the TCP flags:
  * `s` - SYN flag
  * `a` - ACK flag
  * `f` - FIN flag
  * `r` - RST flag
  * `p` - PSH flag
  * `u` - URG flag
  * `e` - ECE flag
  * `c` - CWR flag
  * `n` - NS flag

In this case we find out that port 23 sent reply packet with ACK and RST flags set (typical response for a closed port according to the rfc793).

If we scan an open port, we get no response (unless the firewall is spoofing the responses).

Other types of TCP scans can be conducted by analogy.

TCP NULL scan:

```
cat arp.cache | ./sx tcp null --json -p 23 192.168.0.171
```

TCP Xmas scan:

```
cat arp.cache | ./sx tcp xmas --json -p 23 192.168.0.171
```

### Custom TCP scans

It is possible to send TCP packets with custom TCP flags using `--flags` option.

Let's send TCP packet with SYN, FIN and ACK flags set to fingerprint remote OS:

```
cat arp.cache | ./sx tcp --flags syn,fin,ack --json -p 23 192.168.0.171
```

Windows and MacOS will not respond to this packet, but Linux will send reply packet with RST flag.

Possible arguments to `--flags` option:
  * `syn` - SYN flag
  * `ack` - ACK flag
  * `fin` - FIN flag
  * `rst` - RST flag
  * `psh` - PSH flag
  * `urg` - URG flag
  * `ece` - ECE flag
  * `cwr` - CWR flag
  * `ns` - NS flag


### UDP scan

`sx` can help investigate open UDP ports. UDP scan exploits RFC1122 Section 4.1.3.1:

> If a datagram arrives addressed to a UDP port for which
> there is no pending LISTEN call, UDP SHOULD send an ICMP
> Port Unreachable message.

Similar to TCP scans, `sx` returns information about all reply ICMP packets for UDP scan. The information contains IP address, ICMP packet type and code set in the reply packet.


For instance, to detect DNS server on host, run:

```
cat arp.cache | ./sx udp --json -p 53 192.168.0.171
```

sample output:

```
{"scan":"udp","ip":"192.168.0.171","icmp":{"type":3,"code":3}}
```

In this case we find out that host sent ICMP reply packet with **Destination Unreachable** type and **Port Unreachable** code (typical response for a closed port according to the rfc1122).

Firewalls typically set ICMP code distinct from **Port Unreachanble** and so can be easily detected.


### Rate limiting

Sometimes you need to limit the speed at which generated packets are sent. This can be done with 
the `--rate` option.

For example, to limit the speed to 1 packet per 5 seconds:

```
cat arp.cache | ./sx tcp --rate 1/5s --json -p 22,80,443 192.168.0.171
```

### Live LAN TCP SYN scanner

As an example of scan composition, you can combine ARP and TCP SYN scans to create live TCP port scanner that periodically scan whole LAN network.

Start live ARP scan and save results to `arp.cache` file:

```
./sx arp 192.168.0.1/24 --live 10s --json | tee arp.cache
```

In another terminal start TCP SYN scan:

```
while true; do cat arp.cache | ./sx tcp -p 1-65535 192.168.0.1/24 --json 2> /dev/null; sleep 30; done
```

### SOCKS5 scan

`sx` can detect live SOCKS5 proxies. To scan, you must specify an IP range or JSONL file with ip/port pairs.

For example, an IP range scan:

```
./sx socks -p 1080 10.0.0.1/16
```

scan ip/port pairs from a file with JSON output:

```
./sx socks --json -f ip_ports_file.jsonl 2> /dev/null | tee results.jsonl
```

Each line of the input file is a json string, which must contain the **ip** and **port** fields.

sample input file:

```
{"ip":"10.0.1.1","port":1080}
{"ip":"10.0.2.2","port":1081}
```

You can also specify a range of ports to scan:

```
./sx socks -p 1080-4567 -f ips_file.jsonl
```

In this case only ip addresses will be taken from the file and the **port** field is no longer necessary.

### Elasticsearch scan

Elasticsearch scan retrieves the cluster information and a list of all indexes along with aliases.

For example, an IP range scan:

```
./sx elastic -p 9200 10.0.0.1/16
```

By default the scan uses the http protocol, to use the https protocol specify the `--proto` option:

```
./sx elastic --proto https -p 9200 10.0.0.1/16
```

scan ip/port pairs from a file with JSON output:

```
./sx elastic --json -f ip_ports_file.jsonl 2> /dev/null | tee results.jsonl
```

Each line of the input file is a json string, which must contain the **ip** and **port** fields.

sample input file:

```
{"ip":"10.0.1.1","port":9200}
{"ip":"10.0.2.2","port":9201}
```

You can also specify a range of ports to scan:

```
./sx elastic -p 9200-9267 -f ips_file.jsonl
```

In this case only ip addresses will be taken from the file and the **port** field is no longer necessary.


## Usage help

```
./sx help
```

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/v-byte-cpu/sx/blob/master/LICENSE) file for the full license text.
