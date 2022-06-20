# OpenSource

![OpenSourcew](https://user-images.githubusercontent.com/97627828/174652864-db0b100b-bf24-4f44-b614-aed5a43e254c.png)

## Initial Enumeration

```
❯ sudo nmap -sS -sV -O -sC -v -p22,80,3000 opensource.htb 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-20 13:41 EDT
Nmap scan report for opensource.htb (10.10.11.164)
Host is up (0.096s latency).

PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp   open     http    Werkzeug/2.1.2 Python/3.10.3
3000/tcp filtered ppp
```
Comenzaremos interactuando con el puerto 80.

![image](https://user-images.githubusercontent.com/97627828/174655163-f66d3f8c-2586-4b3a-9bba-ebcf6f5a5861.png)

Tras inspeccionar el código fuente de la web se encuentra lo siguiente:
- /download: permite descargar un archivo .ZIP con lo que parece el código fuente de la app que permite la carga de archivos al servidor web.

  ![image](https://user-images.githubusercontent.com/97627828/174656635-94cacc71-e4a9-4998-8a45-6ee78094a71c.png)

- /upcloud: función de carga de archivos al wervidor web.

  ![image](https://user-images.githubusercontent.com/97627828/174657055-234ac1d4-be90-409f-b3c5-5e00dcda9820.png)

- /uploads/nombre-del-archivo-subido (url en la que la página almacena los archivos que se suben, al visitarla se descarga el archivo subido previamente).

  ![image](https://user-images.githubusercontent.com/97627828/174657164-0126a1e7-afbc-4e28-b9c7-d1f150139f74.png)


Para continuar descubriendo directorios, se utiliza "gobuster"
```
❯ sudo gobuster dir -u http://opensource.htb -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt                                                                                                                   
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://opensource.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/06/20 13:57:07 Starting gobuster in directory enumeration mode
===============================================================
/download             (Status: 200) [Size: 2489147]
/console              (Status: 200) [Size: 1563] 
