import subprocess
import sys
import re

# Puertos comunes para escanear en una red con -PS y -PA
ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
         993, 995, 1723, 3306, 3389, 5900, 8080]

def run_nmap(ip_cidr):
    # Comando Nmap básico para escanear puertos y servicios
    command = [
        "sudo", "nmap", "-sS", "-T3", "-p-", "-sV", "--version-intensity", "1",
        "-Pn", "-v", "--randomize-hosts", "-f", "-D", "RND:10",
        "-PS80,443,22", "-PA80,443,22", ip_cidr
    ]
    
    try:
        # Ejecutar el comando y capturar la salida
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout
        print(output)
        
        if result.stderr:
            print(f"Error: {result.stderr}", file=sys.stderr)

        # Analizar la salida para obtener TTL, tamaño de ventana y realizar banner grabbing
        determine_os(output)
        banner_grabbing(output, ip_cidr)
        
    except Exception as e:
        print(f"Exception occurred: {e}", file=sys.stderr)

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

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python nmap_scan.py <IP/CIDR>")
        sys.exit(1)

    ip_cidr = sys.argv[1]
    run_nmap(ip_cidr)