import subprocess
import sys
import re

# Puertos comunes para escanear en una red con -PS y -PA
common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
         993, 995, 1723, 3306, 3389, 5900, 8080]

def run_nmap(ip):
    # Convertir la lista de puertos a una cadena separada por comas
    ports_str = ",".join(map(str, common_ports))
    
    # Comando Nmap para escanear puertos y servicios
    command = [
        "sudo", "nmap", "-sS", "-T3", "-p-", "-sV", "--version-intensity", "1",
        "-Pn", "-v", "--randomize-hosts", "-f", "-D", "RND:10",
        f"-PS{ports_str}", f"-PA{ports_str}", ip
    ]
    
    # Prueba ejecución de comando
    func_aux_command(command)
    
    # try:
    #     # Ejecutar el comando y capturar la salida
    #     result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    #     output = result.stdout
    #     print(output)
        
    #     if result.stderr:
    #         print(f"Error: {result.stderr}", file=sys.stderr)

    #     # Analizar la salida para obtener TTL, tamaño de ventana y realizar banner grabbing
    #     determine_os(output)
    #     banner_grabbing(output, ip_cidr)
        
    # except Exception as e:
    #     print(f"Exception occurred: {e}", file=sys.stderr)
        
def func_aux_command(command):
    # Construir el comando como una cadena de texto
    command_str = " ".join(command)
    
    # Imprimir el comando
    print(command_str)
    

def determine_os(nmap_output):
    # Patrón para capturar TTL y tamaño de ventana
    ttl_pattern = re.compile(r"ttl=(\d+)")
    window_pattern = re.compile(r"window=(\d+)")
    
    ttls = ttl_pattern.findall(nmap_output)
    windows = window_pattern.findall(nmap_output)
    
    if ttls:
        print("\n[+] TTL Values Detected:")
        for ttl in ttls:
            os_type = guess_os_by_ttl(int(ttl))
            print(f"  TTL: {ttl} - Suggested OS: {os_type}")
    
    if windows:
        print("\n[+] TCP Window Sizes Detected:")
        for window in windows:
            os_type = guess_os_by_window(int(window))
            print(f"  Window Size: {window} - Suggested OS: {os_type}")

def guess_os_by_ttl(ttl):
    if ttl == 128:
        return "Windows"
    elif ttl == 64:
        return "Linux/Unix"
    elif ttl == 255:
        return "Cisco/Network Device"
    else:
        return "Unknown"

def guess_os_by_window(window):
    if window == 65535:
        return "Windows"
    elif window == 5840:
        return "Linux"
    elif window == 16384:
        return "OpenBSD"
    else:
        return "Unknown"

def banner_grabbing(nmap_output, ip_cidr):
    # Extraer puertos abiertos
    open_ports_pattern = re.compile(r"(\d+)/tcp\s+open")
    open_ports = open_ports_pattern.findall(nmap_output)
    
    if not open_ports:
        print("\n[+] No open ports found for banner grabbing.")
        return
    
    for port in open_ports:
        print(f"\n[+] Banner grabbing on port {port}")
        banner_command = ["sudo", "nmap", "-sV", "-p", port, "--script=banner", ip_cidr]
        
        try:
            # Ejecutar el comando y capturar la salida
            result = subprocess.run(banner_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            banner_output = result.stdout
            print(banner_output)
            
            if result.stderr:
                print(f"Error: {result.stderr}", file=sys.stderr)
        except Exception as e:
            print(f"Exception occurred: {e}", file=sys.stderr)     

# Función para validar la entrada del usuario
def validate_parameter(entrada):
    # Verificar si la entrada una dir. IP de red con CIDR
    if '/' in entrada:
        ip, cidr = entrada.split('/')
        if validate_ip(ip) and (cidr.isdigit() and 0 <= int(cidr) <= 32):
            return "cidr", entrada
        else: 
            return "incorrect_format", None
    else:
        # Verificar si la entrada es una dirección IP de un host
        if validate_ip(entrada):
            return "ip", entrada
        else:
            return "incorrect_format", None
    
def validate_ip(ip):
    # Validar que la IP tenga 4 octetos y cada uno sea un número entre 0 y 255
    octetos = ip.split('.')
    if len(octetos) != 4:
        return False
    for octeto in octetos:
        if not octeto.isdigit() or not 0 <= int(octeto) <= 255:
            return False
    return True

if __name__ == "__main__":    
    entrada_usuario = input("Ingrese una dirección IP o red con CIDR: ")
    tipo_entrada, ip = validate_parameter(entrada_usuario)
    
    if tipo_entrada == "cidr":
        print(f"Procesando red CIDR: {entrada_usuario}")
        # Llamar a la función para escanear la red CIDR
        run_nmap(ip)
        
    elif tipo_entrada == "ip":
        print(f"Procesando dirección IP: {entrada_usuario}")
        # Llamar a la función para escanear la dirección IP
        run_nmap(ip)
        
    else:
        print("La entrada es incorrecta. Por favor, ingrese una dirección IP válida o una red con CIDR.")
        sys.exit(1)