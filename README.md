# hassh-utils

## Docker

You can get the dockerized version of hassh.py from my Docker repository: https://hub.docker.com/r/0x4d31/hassh/

```
docker pull 0x4d31/hassh
```

## Nmap NSE Script

[ssh-hassh](ssh-hassh.nse) NSE script reports hasshServer (i.e. SSH
Server Fingerprint) and hasshServerAlgorithms for the target SSH
server. The resulting hassh is compared to a list of known hasshServer
values to attempt to fingerprint it.


Basic usage:
```
 % nmap --script ssh-hassh.nse -p 22  192.168.10.136

Starting Nmap 7.60 ( https://nmap.org ) at 2019-09-30 20:45 PDT
Nmap scan report for mikrotik.planethacker.net (192.168.10.136)
Host is up (0.0063s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hassh:
|   Server Identification String: SSH-2.0-ROSSSH
|   hasshServer: 592ac2fb1645c3dc26ede0a59cd46957
|_  hasshServer Guess: SSH-2.0-ROSSSH (100%)

Nmap done: 1 IP address (1 host up) scanned in 0.30 seconds
```


A database file can be specified. See [Nmap Documentation](https://nmap.org/book/data-files-replacing-data-files.html) for more info on how Nmap handles custom data files. Generally, placing databases in /usr/share/nmap/nselib/data/ will work:
```
 % nmap --script ssh-hassh.nse --script-args database=hasshd 192.168.10.136
```


The client's identification string can also be specified if you want to use something besides the default value of _SSH-2.0-Nmap-SSH-HASSH_. Note: this must be formatted correctly; SSH-VERSION-STRING:
```
% nmap --script ssh-hassh.nse --script-args client_string=SSH-2.0-asdf -p 22 192.168.10.136
```

Increasing the verbosity with -v by will display the algorithms:
```
 % nmap --script ssh-hassh.nse -p 22 --open -Pn 192.168.10.136 -oX test.xml -v

...snip...

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hassh:
|   Server Identification String: SSH-2.0-ROSSSH
|   hasshServer: 592ac2fb1645c3dc26ede0a59cd46957
|   hasshServer Guess: SSH-2.0-ROSSSH (100%)
|_  hasshServer Algorithms: diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1;aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc,blowfish-cbc,3des-cbc;hmac-sha1,hmac-md5;none

...snip...
```

Increasing the verbosity higher with -vv will list the algorithms:
```
 % nmap --script ssh-hassh.nse -p 22 --open -Pn 192.168.10.136 -oX test.xml -vv

...snip...

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
| ssh-hassh:
|   Server Identification String: SSH-2.0-ROSSSH
|   hasshServer: 592ac2fb1645c3dc26ede0a59cd46957
|   hasshServer Guess: SSH-2.0-ROSSSH (100%)
|   kex_algorithms: diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
|   encryption_algorithms: aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc,blowfish-cbc,3des-cbc
|   mac_algorithms: hmac-sha1,hmac-md5
|   compression_algorithms: none
|_  server_host_key_algorithms: ssh-dss,ssh-rsa

...snip...
```
