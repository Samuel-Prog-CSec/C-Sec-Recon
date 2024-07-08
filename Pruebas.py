import subprocess
import sys
import re
import random
import argparse
import ipaddress
import xml.etree.ElementTree as ET

# Puertos comunes para escanear en una red con -PS y -PA
common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                993, 995, 1723, 3306, 3389, 5900, 8080]

def run_nmap(ip, scan_type="tcp", is_ipv6=False, output_file="scan_results.xml"):
    # Convertir la lista de puertos a una cadena separada por comas
    ports_str = ",".join(map(str, common_ports))
    
    # Longitud de datos extra para enviar en las cabezeras de los paquetes
    extra_data_len = random.randint(5, 10)
    
    # Comando base de Nmap
    command = [
        "sudo", "nmap", "-T3", "-p-", "-sV", "--version-intensity", "5",
        "-Pn", "-v", "--randomize-hosts", "-f", "-n", "-D", "RND:10", f"--data-length={extra_data_len}",
        f"-PS{ports_str}", f"-PA{ports_str}", "--min-rate=5000", ip, "-oX", output_file
    ]
    
    if scan_type == "udp":
        command.insert(3, "-sU")
    elif scan_type == "sctp":
        command.insert(3, "-sY")
    elif scan_type == "icmp":
        command.insert(3, "-PE")
    else:  # Default to TCP SYN scan
        command.insert(3, "-sS")

    if is_ipv6:
        command.insert(3, "-6")
    
    # Prueba ejecución de comando
    func_aux_command(command)
    
    try:
        # Ejecutar el comando y capturar la salida en tiempo real
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        output = ""
        while True:
            line = process.stdout.readline()
            if line == '' and process.poll() is not None:
                break
            if line:
                print(line.strip())
                output += line

        rc = process.poll()
        
        if rc != 0:
            for line in process.stderr:
                print(f"Error: {line}", file=sys.stderr)

        return output
        
    except Exception as e:
        print(f"Exception occurred: {e}", file=sys.stderr)
        return None
        
def func_aux_command(command):
    # Construir el comando como una cadena de texto
    command_str = " ".join(command)
    
    # Imprimir el comando
    print(f"Ejecutando: {command_str}")

def check_closed_ports(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        closed_ports = 0
        filtered_ports = 0
        ignored_ports = 0
        
        for port in root.findall(".//port"):
            state = port.find('state').get('state')
            if state == "closed":
                closed_ports += 1
            elif state == "filtered":
                filtered_ports += 1
            elif state == "ignored":
                ignored_ports += 1
        
        total_ports = closed_ports + filtered_ports + ignored_ports
        
        if closed_ports == total_ports:
            print("\n[+] Todos los puertos están cerrados.")
        elif filtered_ports == total_ports:
            print("\n[+] Todos los puertos están filtrados.")
        elif ignored_ports == total_ports:
            print("\n[+] Todos los puertos están ignorados.")
        else:
            print("\n[+] Escaneo completado. Puertos abiertos/filtrados detectados.")

    except ET.ParseError as e:
        print(f"Error al analizar el archivo XML: {e}", file=sys.stderr)
    except Exception as e:
        print(f"Exception occurred: {e}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(description="Script de escaneo de puertos y servicios usando Nmap.")
    parser.add_argument("target", help="Dirección IP o red con CIDR a escanear.")
    parser.add_argument("--output", help="Archivo para guardar los resultados del escaneo en formato XML.", default="scan_results.xml")
    parser.add_argument("--scan-type", choices=["tcp", "udp", "icmp", "sctp"], default="tcp", 
                        help="Tipo de escaneo a realizar: tcp, udp, icmp, sctp.")
    
    args = parser.parse_args()
    
    tipo_entrada, ip = validate_parameter(args.target)
    is_ipv6 = ":" in ip
    
    if tipo_entrada in ["cidr", "ip"]:
        print(f"Procesando {tipo_entrada}: {args.target}")
        output = run_nmap(ip, args.scan_type, is_ipv6, args.output)
        
        if output:
            print(f"Resultados guardados en {args.output}")
            check_closed_ports(args.output)
        
    else:
        print("La entrada es incorrecta. Por favor, ingrese una dirección IP válida o una red con CIDR.")
        sys.exit(1)

def validate_parameter(entrada):
    try:
        # Verificar si la entrada es una dirección IPv4, IPv6 o una red CIDR
        ip = ipaddress.ip_network(entrada, strict=False)
        return "cidr" if ip.prefixlen < ip.max_prefixlen else "ip", str(ip)
    except ValueError:
        return "incorrect_format", None

if __name__ == "__main__":
    main()