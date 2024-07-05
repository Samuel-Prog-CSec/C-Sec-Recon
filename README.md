# Escaneo con Nmap

Este script en Python realiza un escaneo de red utilizando Nmap, obteniendo información detallada de puertos, servicios y sistemas operativos de los hosts en la red, todo mientras se intenta ser lo más discreto posible para evadir detecciones de seguridad.

## Explicación del Comando Nmap Utilizado

```sh
sudo nmap -sS -T3 -p- -sV --version-intensity 1 -Pn -v --randomize-hosts -f -D RND:10 -PS80,443,22 -PA80,443,22 <ip>
```

sudo nmap: Ejecuta Nmap con privilegios de superusuario.
-sS: Realiza un escaneo SYN.
-T3: Tiempo de escaneo moderado.
-p-: Escanea todos los puertos (0-65535).
-sV: Detección de versiones de servicios.
--version-intensity 1: Intensidad baja de detección de versiones.
-Pn: Desactiva el escaneo de ping (asume que los hosts están activos).
-v: Modo verbose, proporciona más detalles en la salida.
--randomize-hosts: Aleatoriza el orden de escaneo de hosts.
-f: Fragmenta los paquetes para evadir la detección por IDS.
-D RND:10: Usa 10 direcciones IP aleatorias como señuelos.
-PS80,443,22: Envía paquetes SYN a los puertos 80, 443 y 22.
-PA80,443,22: Envía paquetes ACK a los puertos 80, 443 y 22.
<ip>: Dirección IP y el CIDR que se pasa como argumento al script.
Técnicas para Determinar el SO sin -O o -A
TTL y Ventana de Tamaño en Respuestas
TTL (Time To Live) y el tamaño de la ventana TCP en las respuestas pueden dar pistas sobre el SO.
Los sistemas operativos diferentes usan valores predeterminados de TTL y tamaño de ventana diferentes.
Banner Grabbing
Muchos servicios y servidores envían información de su SO en los banners de sus respuestas.
Por ejemplo, un servidor web puede revelar su SO en la cabecera HTTP.
Explicación de la Implementación
Determinación del SO
TTL y Tamaño de Ventana
Utilizamos métodos para detectar TTL y tamaños de ventana.
Funciones de Guía: guess_os_by_ttl y guess_os_by_window proporcionan suposiciones sobre el SO basadas en estos valores.
Banner Grabbing
Patrón de Puertos Abiertos: Extraemos los puertos abiertos de la salida de Nmap utilizando una expresión regular.
Comando Nmap para Banner Grabbing: Para cada puerto abierto, ejecutamos Nmap con el script banner para obtener información del banner del servicio.
Salida de Banner: Capturamos y mostramos la salida del banner grabbing.
