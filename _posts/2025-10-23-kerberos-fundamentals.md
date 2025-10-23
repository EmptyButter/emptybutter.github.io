---
title: "Kerberos Fundamentals"
categories:
  - Tutorial
media_subpath: /assets/posts/2025-10-23-kerberos-fundamentals/
image: kerberos_wide.png
description: This post outlines the authentication flow of the Kerberos protocol and the exact data structures for each message during transfer.
tags: []
---

I found most existing Kerberos protocol tutorials unsatisfactory — they’re either too noisy or lack sufficient detail. So I created this post with simplified, intuitive yet accurate diagrams. I also dive into the RFC to show the exact data structure for each message and where key information is stored during transfer.

## Ticket Definition
A Ticket Granting Ticket (TGT) and a Ticket Granting Service (TGS) ticket share a similar structure, as defined in the  [RFC4120](https://www.ietf.org/rfc/rfc4120.txt). Each consists of an unencrypted section that contains metadata, and an encrypted section that holds sensitive information such as credentials and session keys. 
```
   Ticket          ::= [APPLICATION 1] SEQUENCE {

           tkt-vno         [0] INTEGER (5),  
           realm           [1] Realm,  
           sname           [2] PrincipalName,  
           enc-part        [3] EncryptedData -- EncTicketPart  
   } 
  
   -- Encrypted part of ticket  
   EncTicketPart   ::= [APPLICATION 3] SEQUENCE {  
           flags                   [0] TicketFlags,  
           key                     [1] EncryptionKey,  
           crealm                  [2] Realm,  
           cname                   [3] PrincipalName,  
           transited               [4] TransitedEncoding,  
           authtime                [5] KerberosTime,  
           starttime               [6] KerberosTime OPTIONAL,  
           endtime                 [7] KerberosTime,  
           renew-till              [8] KerberosTime OPTIONAL,  
           caddr                   [9] HostAddresses OPTIONAL,  
           authorization-data      [10] AuthorizationData OPTIONAL  
   }  
  
   -- encoded Transited field  
   TransitedEncoding       ::= SEQUENCE {  
           tr-type         [0] Int32 -- must be registered --,  
           contents        [1] OCTET STRING  
   }  
  
   TicketFlags     ::= KerberosFlags  
           -- reserved(0),  
           -- forwardable(1),  
           -- forwarded(2),  
           -- proxiable(3),  
           -- proxy(4),  
           -- may-postdate(5),  
           -- postdated(6),  
           -- invalid(7),  
           -- renewable(8),  
           -- initial(9),  
           -- pre-authent(10),  
           -- hw-authent(11),  
   -- the following are new since 1510  
           -- transited-policy-checked(12),  
           -- ok-as-delegate(13)
```

## Workflow (High-level)
![](Pasted%20image%2020251020053003.png)
![](Pasted%20image%2020251020054434.png){: w="350" h="50"}

Note: The red key here is technically the long-term key of the Ticket Granting Service, which is a component of the KDC. For simplicity and readability, it is referred to here as the KDC long-term key.

Note: Technically, TGS stands for Ticket Granting Service, not a ticket. However, for simplicity and readability, I use TGS to refer to the Ticket Granting Service _ticket_, in contrast to the TGT.

## AS-REQ
Authentication Service Request: Sent by the client to the KDC to request a TGT on behalf of the user.
![](Pasted%20image%2020251020053546.png)

An authenticator is encrypted with the user's long-term key, which is also held by the KDC, to verify the user's identity. Specifically, it sits in the `padata` field.
```
AS-REQ          ::= [APPLICATION 10] KDC-REQ  
  
KDC-REQ         ::= SEQUENCE {  
        -- NOTE: first tag is [1], not [0]  
        pvno            [1] INTEGER (5) ,  
        msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),  
        padata          [3] SEQUENCE OF PA-DATA OPTIONAL  <========== Authenticator
                                    -- NOTE: not empty --,  
        req-body        [4] KDC-REQ-BODY  
}  
  
KDC-REQ-BODY    ::= SEQUENCE {  
        kdc-options             [0] KDCOptions,  
        cname                   [1] PrincipalName OPTIONAL  
                                    -- Used only in AS-REQ --, 
        realm                   [2] Realm  
                                    -- Server's realm  
                                    -- Also client's in AS-REQ --,  
        sname                   [3] PrincipalName OPTIONAL,  
        from                    [4] KerberosTime OPTIONAL,  
        till                    [5] KerberosTime,  
        rtime                   [6] KerberosTime OPTIONAL,  
        nonce                   [7] UInt32,  
        etype                   [8] SEQUENCE OF Int32 -- EncryptionType  
                                    -- in preference order --,  
        addresses               [9] HostAddresses OPTIONAL,  
        enc-authorization-data  [10] EncryptedData OPTIONAL  
                                    -- AuthorizationData --,  
        additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL  
                                       -- NOTE: not empty  
}  
```

![](Pasted%20image%2020251020064541.png)
## AS-REP
Authentication Server Response: Sent by the KDC to the client in response to an AS-REQ. It contains the TGT and a user-KDC session key. 
![](Pasted%20image%2020251020053643.png)
The TGT sits in the `ticket` field. The encrypted session key sits in the `key` field of the `enc-part`.
```
AS-REP          ::= [APPLICATION 11] KDC-REP  
  
TGS-REP         ::= [APPLICATION 13] KDC-REP  
  
  
KDC-REP         ::= SEQUENCE {  
        pvno            [0] INTEGER (5),  
        msg-type        [1] INTEGER (11 -- AS -- | 13 -- TGS --),  
        padata          [2] SEQUENCE OF PA-DATA OPTIONAL  
                                -- NOTE: not empty --,  
        crealm          [3] Realm,  
        cname           [4] PrincipalName,        
        ticket          [5] Ticket,  <====== TGT        
        enc-part        [6] EncryptedData  
                                -- EncASRepPart or EncTGSRepPart,  
                                -- as appropriate  
}  
  
EncASRepPart    ::= [APPLICATION 25] EncKDCRepPart   
  
EncKDCRepPart   ::= SEQUENCE {  
        key             [0] EncryptionKey,  <======== Encrypted session key      
        last-req        [1] LastReq,  
        nonce           [2] UInt32,  
        key-expiration  [3] KerberosTime OPTIONAL,  
        flags           [4] TicketFlags,  
        authtime        [5] KerberosTime,  
        starttime       [6] KerberosTime OPTIONAL,  
        endtime         [7] KerberosTime,  
        renew-till      [8] KerberosTime OPTIONAL,  
        srealm          [9] Realm,  
        sname           [10] PrincipalName,  
        caddr           [11] HostAddresses OPTIONAL  
}  
  
LastReq         ::=     SEQUENCE OF SEQUENCE {  
        lr-type         [0] Int32,  
        lr-value        [1] KerberosTime  
}
```

![](Pasted%20image%2020251020064606.png)
## TGS-REQ
Ticket Granting Service Request: Sent by the client to the KDC to request access to a specific service. It includes the TGT obtained earlier and a new authenticator encrypted with the user-KDC session key.
![](Pasted%20image%2020251020053717.png)

Both the TGT and the authenticator sit in the `padata` field. The target SPN sits in the `sname` field of the `req-body`.
```
TGS-REQ         ::= [APPLICATION 12] KDC-REQ  
  
KDC-REQ         ::= SEQUENCE {  
        -- NOTE: first tag is [1], not [0]  
        pvno            [1] INTEGER (5) ,  
        msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),  
        padata          [3] SEQUENCE OF PA-DATA OPTIONAL  <========= Authenticator + TGT  
                            -- NOTE: not empty --,  
        req-body        [4] KDC-REQ-BODY  
}  
  
KDC-REQ-BODY    ::= SEQUENCE {  
        kdc-options             [0] KDCOptions,  
        cname                   [1] PrincipalName OPTIONAL  
                                    -- Used only in AS-REQ --,  
        realm                   [2] Realm  
                                    -- Server's realm  
                                    -- Also client's in AS-REQ --,  
        sname                   [3] PrincipalName OPTIONAL,  <========= Target SPN  
        from                    [4] KerberosTime OPTIONAL,  
        till                    [5] KerberosTime,  
        rtime                   [6] KerberosTime OPTIONAL,  
        nonce                   [7] UInt32,  
        etype                   [8] SEQUENCE OF Int32 -- EncryptionType  
                                    -- in preference order --,  
        addresses               [9] HostAddresses OPTIONAL,  
        enc-authorization-data  [10] EncryptedData OPTIONAL  
                                    -- AuthorizationData --,  
        additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL  
                                       -- NOTE: not empty  
}  
```

![](Pasted%20image%2020251020064510.png)
## TGS-REP
Ticket Granting Service Response: Sent by the KDC to the client in response to a TGS-REQ.  
It contains a service ticket and a new session key.
![](Pasted%20image%2020251020053742.png)

The TGS sits in the `ticket` field. The encrypted session key sits in the `key` field of the `enc-part`.
```
TGS-REP         ::= [APPLICATION 13] KDC-REP  
  
KDC-REP         ::= SEQUENCE {  
        pvno            [0] INTEGER (5),  
        msg-type        [1] INTEGER (11 -- AS -- | 13 -- TGS --),  
        padata          [2] SEQUENCE OF PA-DATA OPTIONAL  
                                -- NOTE: not empty --,  
        crealm          [3] Realm,  
        cname           [4] PrincipalName,  
        ticket          [5] Ticket,  <============ TGS        
        enc-part        [6] EncryptedData  
                                -- EncASRepPart or EncTGSRepPart,  
                                -- as appropriate  
}  

EncTGSRepPart   ::= [APPLICATION 26] EncKDCRepPart  
  
EncKDCRepPart   ::= SEQUENCE {  
        key             [0] EncryptionKey,  <=========== Encrypted session key
        last-req        [1] LastReq,  
        nonce           [2] UInt32,  
        key-expiration  [3] KerberosTime OPTIONAL,  
        flags           [4] TicketFlags,  
        authtime        [5] KerberosTime,  
        starttime       [6] KerberosTime OPTIONAL,  
        endtime         [7] KerberosTime,  
        renew-till      [8] KerberosTime OPTIONAL,  
        srealm          [9] Realm,  
        sname           [10] PrincipalName,  
        caddr           [11] HostAddresses OPTIONAL  
}  
  
LastReq         ::=     SEQUENCE OF SEQUENCE {  
        lr-type         [0] Int32,  
        lr-value        [1] KerberosTime  
}
```

![](Pasted%20image%2020251020070804.png)
## AP-REQ
Application Request: Sent by the client to the target service to prove its identity and request access.  It includes the TGS ticket and a fresh authenticator encrypted with the user-service session key.
![](Pasted%20image%2020251020080723.png)
```
AP-REQ          ::= [APPLICATION 14] SEQUENCE {
	   pvno            [0] INTEGER (5),
	   msg-type        [1] INTEGER (14),
	   ap-options      [2] APOptions,
	   ticket          [3] Ticket,
	   authenticator   [4] EncryptedData -- Authenticator  <======= Authenticator
}

APOptions       ::= KerberosFlags
	   -- reserved(0),
	   -- use-session-key(1),
	   -- mutual-required(2)
```

![](Pasted%20image%2020251020071627.png)
## AP-REP
Application Reply: Sent by the service to the client in response to an AP-REQ to confirm mutual authentication.  It contains a timestamp encrypted with the session key, proving that the service also possesses the shared key.
```
AP-REP          ::= [APPLICATION 15] SEQUENCE {
	   pvno            [0] INTEGER (5),
	   msg-type        [1] INTEGER (15),
	   enc-part        [2] EncryptedData -- EncAPRepPart
}

EncAPRepPart    ::= [APPLICATION 27] SEQUENCE {
	   ctime           [0] KerberosTime,
	   cusec           [1] Microseconds,
	   subkey          [2] EncryptionKey OPTIONAL,
	   seq-number      [3] UInt32 OPTIONAL
}
```
