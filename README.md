# hassh-utils

## Docker

You can get the dockerized version of hassh.py from my Docker repository: https://hub.docker.com/r/0x4d31/hassh/

```
docker pull 0x4d31/hassh
```

## Nmap NSE Script

[ssh-hassh](ssh-hassh.nse) nse script reports hasshServer (i.e. SSH Server Fingerprint) and hasshServerAlgorithms for the target SSH server.

```
adel$ nmap -p 22 --script ssh-hassh github.com -oX hassh.xml

Starting Nmap 7.00 ( https://nmap.org ) at 2018-09-26 03:13 AEST
Nmap scan report for github.com (192.30.255.112)
Host is up (0.18s latency).
Other addresses for github.com (not scanned): 192.30.255.113
rDNS record for 192.30.255.112: lb-192-30-255-112-sea.github.com
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hassh: 
|   Server Identification String: SSH-2.0-libssh_0.7.0
|   hasshServer: 85a34ecc072b7fee11a05e8208ffc2a2
|_  hasshServer Algorithms: curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256;chacha20-poly1305@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc;hmac-sha2-256,hmac-sha2-512,hmac-sha1;none,zlib,zlib@openssh.com

Nmap done: 1 IP address (1 host up) scanned in 1.47 seconds
```
