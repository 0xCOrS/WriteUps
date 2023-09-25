# Agile Machine

## Service Enumeration

To begin with, I start scanning all the ports on the target to obtain an overall picture of the target. For this I use following command ```sudo nmap -sS -p- --min-rate 10000 -v agile.htb```

![Imagen1](images/Imagen1.png)

New scan is made adding the -Pn flag to treat the host as if it was up ```sudo nmap -Pn -p- --min-rate 10000 agile.htb```

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/a0b05ef3-6c03-49a7-959a-9250f86e8793)

Once the open ports are known, I began the service enumeration process. To do this the follow-ing command was used ```sudo nmap -sS p22,80 -sV -O agile.htb```

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/7477eab1-7712-4b50-bb40-82e179de733b)

### Port Scan Results

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/c46d1b86-04f5-4946-8327-7236fc598d4b)

### HTTP Enumeration

The first step taken was to scan using gobuster in order to find directories and other functions in the service. The command used was ```sudo gobuster dir -u http://agile.htb -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt```

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/49888409-08ce-4553-bce3-a6bba3328bfc)

The fact that 0 results were found with the previous scan is quite unique. Just to check, I try to visit the webpage without specifying any domain, just using the IP address (and Burpsuite). As expected, the specified domain was not correct.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/b6bdc376-69b0-4735-b12a-72fab5204166)

With this in mind, I re-run the directory scan ```sudo gobuster dir -u http://superpass.htb -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -x conf,txt,php -t 50```

To gain a deeper knowledge of the web logic, I start to manually interact with the webpage using burpsuite to inspect the HTTP requests. As shown in the picture below, it appears to be a password manager. 

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/6cc81221-5e95-4707-9a6c-937d26f33076)

In “/account/register” It allows to register new users, so I register myself as “cosme:cosme”.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/c4295af6-d71f-4440-9925-c8e90158661b)

As a result, the server HTTP response code is 500 indicating that some error occurred.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/b94188e0-9f18-4809-b3ba-2fd2d86951a7)

As it can be seen in the image below, the server throws an “SQL Operational Error” and shows the debugger’s traceback of the error.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/31bb85c9-f58f-4a1a-a192-5f88c780656d)

The fact that the Debugger mode is active is very interesting because it can lead to code execution as it allows to open a python interactive console. This console can be protected by a PIN, however, if we can access some specific files in the server through LFI, we could potentially generate a PIN and open the interactive python console.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/c5c957ae-6e73-4a54-84fc-f27eb0a0780e)

The console is indeed protected by a PIN. The registering error does not happen always and so, I can register and login to keep checking the web functionalities.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/27c9f152-f674-42d3-972a-653a095829b8)

Once logged in, I am redirected to “/vault”, where I can add new passwords, and (what is more interesting) exporting the ones that I have previously added.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/91be1c32-e06c-4058-a3cd-8d7e9cb16169)

After adding some passwords, I export everything and among all the generated HTTP requests it points out the one where I download the CSV file.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/750e6491-7b05-4f1a-b51b-5c1d493044f4)


Using a LFI dictionary obtained online (“https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_linux.txt”) I automate the search, getting a positive result and thus, finding a LFI vulnerability.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/677d5c8f-8519-4f8e-bd90-ab2ef0380fb3)

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/df7072dc-b32a-42d5-ab95-77c2e999ad6d)

## Initial Access - Werkzeug Debug Console Pin Bypass

**Vulnerability Explanation**: Werkzeug debug console requires a PIN by default. If a LFI vulner-ability is found (LFI explained in Service Enumeration), it is possible to obtain the necessary information about the system and generate a valid PIN to open a python interactive console on the server.

**Vulnerability Fix**: Disable debugger in production.

**Severity**: Critical

**Steps to reproduce the attack**: steps followed for generating a valid PIN were those described in “https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug” and the python code used was found in “https://github.com/wdahlenburg/werkzeug-debug-console-bypass/blob/main/werkzeug-pin-bypass.py”. 

Following information is needed to generate the PIN:

•	username of the user who started this Flask, in this case is ```www-data```

•	modname, in this case is ```flask.app```

•	```getattr(app, '__name__', getattr (app .__ class__, '__name__'))``` in this case is ```wsgi_app```

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/dcdf0d07-2b1a-44e1-a3a0-3a55553157de)

•	```getattr(mod, '__file__', None)``` is the absolute path of app.py in the flask directory, in this case is ```/app/venv/lib/python3.10/site-packages/flask/app.py```

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/9ffbbb62-cd7c-4119-b4e8-b03e18461669)

•	MAC address of the server (found in /sys/class/net/eth0/address), in this case is ```00:50:56:b9:75:e3```

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/7e959a9c-8da1-47f1-9394-7f53498e68a2)

•	Machine Id, which is the result of concatenating ```/etc/machine-id``` and the first line of ```/proc/self/cgroup``` after the last slash.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/7de93d95-3b29-4756-afac-a9b9782d6d45)

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/2cd1b9a7-b15a-4b39-93bb-fe9969a1b575)

After gathering all the information and adding it to the script, the code to generate the PIN is the following.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/74af6aca-a04c-41c5-b2a2-8bf01ba8c975)

Once run, it generates a valid PIN.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/23628549-d01e-460f-ab8f-f44e1cc3f783)

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/5762c7c7-a9b2-4b05-99b4-795e830db368)

After opening the interactive python console, a reverse connection is established and a shell is opened as ```www-data```
Once inside the shell, an interesting file is found ```/app/config_prod.json``` that contains valid MySQL credentials ```superpassuser:dSA6l7q*yIVs$39Ml6ywvgK```

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/27947685-abba-4045-8c3c-8771a8cc0d4f)

Using those credentials, it is possible to access MySQL database where the vaults of other users of the “Superpass Password Manager” are stored. One of the vaults belongs to user “corum” and contains his credentials for “agile” ```corum: 5db7caa1d13cc37c9fc2```

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/99af3065-39ce-4d51-8ff6-4c77cae2711a)

It is possible to authenticate as user “corum” and open a new shell, accessing “user.txt”.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/86563898-6dc4-4ea2-8ca6-1bbfb901f58e)

Once identified as “corum”, inspecting the output of ```ps -ef``` it is found that there are two instances of the application running simultaneously: “wsgi-dev” and “wsgi”.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/8e13b0da-d3b6-406a-90ce-e2b5024447e5)

What it is occurring on the server is a constant testing of “wsgi-dev” app (located in ```/app/app-testing/wsgi-dev.py```) in order to update “wsgi” app (located in ```/app/app/wsgi.py```). This can be checked inspecting ```/app/test_and_update.sh```

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/ccc02c24-40c3-402c-999a-40359a6d9be0)

Checking the available test file found in ```/app/app-testing/tests/functional/test_site_interactively.py``` and current running processes it is found that Chrome is running to debug interactively the app using the remote debug-ging port “41829”. 

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/46985ef7-ab6f-4500-a337-7304d3ec309d)

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/268cac9b-8a29-4373-8ce5-aabf9fe6d8ef)

With this information, chisel is used to establish a tunnel and to interact with the Debugging Instance (running on the target) in my local Chromium browser. For this, a Basic Server Listener is started in my machine on port 8888 (accepting reverse tunnels) which is connected from the target and then a tunnel pointing to the remote debugging port (41829) is established.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/bb6f1fd4-2032-462c-9b72-2bfc11da5f87)

After this, the debugging instance can be accessed using “Chromium”.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/af2d061f-a594-46d6-b57d-3988d4eaad5b)

Once here, valid credentials for user “Edwards” ```edwards:d07867c6267dcb5df0af``` are found as his Vault is opened in the Debugging Instance.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/0de154dc-e392-4613-8a5e-f995fcfaad52)

It is possible to access the target machine vía SSH using those credentials.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/80bb7e62-817a-467f-9686-f4265fc6718b)

## Privilege Escalation - Sudoedit

**Vulnerability Explanation**: In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a "--" argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value (https://nvd.nist.gov/vuln/detail/CVE-2023-22809). 

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/2f7f020d-8ea8-483f-9d66-96c9c18cad52)

As it can be seen in the following picture (Illustration 35), user Edwards is able to execute sudoedit as user “dev_admin” to modify two specific files. However, due to **CVE-2023-22809**, it is possible to modify any file as user dev_admin (“https://www.synacktiv.com/sites/default/files/2023-01/sudo-CVE-2023-22809.pdf”).
 
![image](https://github.com/0xCOrS/WriteUps/assets/97627828/41c48bdc-9a8e-4861-abd3-b20b5fdfb8b5)

**Vulnerability Fix**: Update Sudo Version to the latest Stable Release 1.9.13p3 (https://www.sudo.ws/).

**Severity**: Critical/Medium

**Steps to reproduce the attack**:

Inspecting the running processes, it is possible to observe that there is a cron job that runs ```/bin/bash -c source /app/venv/bin/activate``` regularly as “root”. Checking the file permissions, Group owner is dev_admin.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/c3516a5e-6153-4d6f-bcd0-ed6c2460e633)

Taking all the previous information into account, we can modify the file ```/app/venv/bin/activate``` as user dev_admin and then wait until the cron job executes the file with root privileges. Steps as follows:

1.	Set the environment variable EDITOR adding the extra file to modify.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/bb7aa766-d994-4477-8e53-e07e81dec252)

2.	Modify (as user dev_admin) the contents of ```/app/venv/bin/activate``` through execution of ```sudoedit -u dev_admin /app/config_test.json``` and adding a python reverse shell.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/4cf01c6a-4d6c-4c62-b11f-5a951b2cd0c4)

3.	Set a listener on local port 444 and wait until the cron job executes the modified file.

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/2183b533-f77e-4a22-b61a-7d356c5aa713)

![image](https://github.com/0xCOrS/WriteUps/assets/97627828/1d44cefc-a358-4cbc-9e83-4bfef9e55cf7)




















