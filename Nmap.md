Basic Syntax

```jsx
nmap <scan types> <options> <target>
```

One popular method of scanning is the TCP-SYN scan (-sS), which skips the three-way handshake.

```jsx
sudo nmap -sS localhost
```

## **HOST DISCOVERY**

To find out which system is on the network, use host discover

### Scan Network Range

```jsx
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
```

| **Scanning Options** | **Description** |
| --- | --- |
| `10.129.2.0/24` | Target network range. |
| `-sn` | This disables port scanning. |
| `-oA tnet` | Stores the results in all formats starting with the name 'tnet.’ |

This ought to yield the list of IP addresses available on the designated network.

### Scan IP List

```jsx
sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5
```

| **Scanning Options** | **Description** |
| --- | --- |
| `-sn` | This disables port scanning. |
| `-oA tnet` | Stores the results in all formats starting with the name 'tnet.’ |
| `-iL` | The system performs defined scans against targets in the provided 'hosts.lst' list. |

This checks every IP address in the list and returns the ones that are active or online. PS: Because of firewalls, some hosts might not return as active.

### Scan Multiple IPs

```jsx
sudo nmap -sn -oA tnet 10.129.2.18 10.129.2.19 10.129.2.20| grep for | cut -d" " -f5
```

or

Scanning a specific range

```jsx
sudo nmap -sn -oA tnet 10.129.2.18-20| grep for | cut -d" " -f5
```

### Scan Single Ip to determine if its alive

```jsx
sudo nmap 10.129.2.18 -sn -oA host 
```

or

```jsx
sudo nmap 10.129.2.18 -sn -oA host -PE --reason
```

| **Scanning Options** | **Description** |
| --- | --- |
| `-PE` | The system performs the ping scan by using 'ICMP Echo requests' against the target. |
| `--reason` | Displays the reason for the specific result. |

```jsx
sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace --disable-arp-ping
```

This gives TTL information, which is also useful for figuring out the OS.

## **Host and Port Scanning**

### Scanning Top 10 TCP Ports

```jsx
sudo nmap 10.129.2.28 --top-ports=10
```

### Complete 3 way handshake TCP connection, aka Connect Scan

```jsx
sudo nmap 10.129.2.28 -p 443 --packet-trace --disable-arp-ping -Pn -n --reason -sT
```

| **Scanning Options** | **Description** |
| --- | --- |
| `-p 139` | Scans only the specified port. |
| `--packet-trace` | Shows all packets sent and received. |
| `-n` | Disables DNS resolution. |
| `--disable-arp-ping` | Disables ARP ping. |
| `-Pn` | Disables ICMP Echo requests. |

### Dealing with Filtered Ports

```jsx
sudo nmap 10.129.2.28 -p 445 --packet-trace -n --disable-arp-ping -Pn
```

### UDP Port Scan

```jsx
sudo nmap 10.129.2.28 -F -sU
```

| **Scanning Options** | **Description** |
| --- | --- |
| `-F` | Scans top 100 ports. |
| `-sU` | Performs a UDP scan. |

### Determine if UDP packet arrived or not

```jsx
sudo nmap 10.129.2.28 -sU -Pn -n --disable-arp-ping --packet-trace -p 137 --reason 
```

### Version Scan

```jsx
 sudo nmap 10.129.2.28 -Pn -n --disable-arp-ping --packet-trace -p 445 --reason  -sV
```

## SAVING RESULTS

| **Scanning Options** | **Description** |
| --- | --- |
| `-oN` | Normal output (-oN) with the .nmap file extension |
| `-oG` | Grepable output (-oG) with the .gnmap file extension |
| `-oX` | XML output (-oX) with the .xml file extension |
| `-oA target` | Saves the results in all formats, starting the name of each file with 'target'. |

## Service Enumeration

### Service Version Detection

```jsx
sudo nmap 10.129.2.28 -p- -sV
```

| **Scanning Options** | **Description** |
| --- | --- |
| `-p-` | Scans all ports. |
| `-sV` | Performs service version detection on specified ports. |

### Period Scan

```jsx
sudo nmap 10.129.2.28 -p- -sV --stats-every=5s
```

| **Scanning Options** | **Description** |
| --- | --- |
| `--stats-every=5s` | Shows the progress of the scan every 5 seconds. |

### Verbose Scan

```jsx
sudo nmap 10.129.2.28 -p- -sV -v 
```

or

```jsx
sudo nmap 10.129.2.28 -p- -sV -vv
```

| **Scanning Options** | **Description** |
| --- | --- |
| `-v` | Increases the verbosity of the scan, which displays more detailed information. |

### Non Automated Scan

```jsx
sudo nmap 10.129.2.28 -p- -sV -Pn -n --disable-arp-ping --packet-trace
```

## NMAP SCRIPT ENGINE

| **Category** | **Description** |
| --- | --- |
| `auth` | Determination of authentication credentials. |
| `broadcast` | Scripts, which are used for host discovery by broadcasting and the discovered hosts, can be automatically added to the remaining scans. |
| `brute` | Executes scripts that try to log in to the respective service by brute-forcing with credentials. |
| `default` | Default scripts executed by using the `-sC` option. |
| `discovery` | Evaluation of accessible services. |
| `dos` | These scripts are used to check services for denial of service vulnerabilities and are used less as it harms the services. |
| `exploit` | This category of scripts tries to exploit known vulnerabilities for the scanned port. |
| `external` | Scripts that use external services for further processing. |
| `fuzzer` | This uses scripts to identify vulnerabilities and unexpected packet handling by sending different fields, which can take much time. |
| `intrusive` | Intrusive scripts that could negatively affect the target system. |
| `malware` | Checks if some malware infects the target system. |
| `safe` | Defensive scripts that do not perform intrusive and destructive access. |
| `version` | Extension for service detection. |
| `vuln` | Identification of specific vulnerabilities. |

### Default Script

```jsx
sudo nmap <target> -sC
```

### Specific Script

```jsx
sudo nmap <target> --script <category>
```

### Defined Script

```jsx
sudo nmap <target> --script <script-name>,<script-name>,…
```

### Aggressive Scan

```jsx
 sudo nmap 10.129.2.28 -p 80 -A
```

### Vulnerability Scan

```jsx
sudo nmap 10.129.2.28 -p 80 -sV --script vuln 
```

# PERFORMANCE

### Optimized RTT (Round Trip Time)

```jsx
sudo nmap 10.129.2.0/24 -F --initial-rtt-timeout 50ms --max-rtt-timeout 100ms
```

| **Scanning Options** | **Description** |
| --- | --- |
| `-F` | Scans top 100 ports. |
| `--initial-rtt-timeout 50ms` | Sets the specified time value as initial RTT timeout. |
| `--max-rtt-timeout 100ms` | Sets the specified time value as maximum RTT timeout. |

### Max Retries

```jsx
sudo nmap 10.129.2.0/24 -F --max-retries 0
```

| **Scanning Options** | **Description** |
| --- | --- |
| `--max-retries 0` | Sets the number of retries that will be performed during the scan. |

### Rates

```jsx
sudo nmap 10.129.2.0/24 -F --min-rate 300
```

### Timing

- `T 0` / `T paranoid`
- `T 1` / `T sneaky`
- `T 2` / `T polite`
- `T 3` / `T normal`
- `T 4` / `T aggressive`
- `T 5` / `T insane`

### Extras

`grep for`: This command filters the input, selecting only those lines that contain the string "for.”

`cut -d" " -f5`: The filtered lines are then passed to the cut command, which uses a space (" ") as the delimiter and extracts the fifth field from each line.

`-oA` : `-oA <basename>` is an Nmap output option that tells Nmap to store scan results in all three major formats — Normal (`.nmap`), XML (`.xml`), and Grepable (`.gnmap`)—using a single base filename.

`xsltproc nmapscan.xml -o target.html` : transform xml into HTML
