import socket
import threading
import datetime

# Common ports and their typical services
COMMON_PORTS = {
    20: "FTP Data Transfer",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Proxy"
}

# Basic vulnerability hints for demo purposes
VULN_HINTS = {
    21: "Anonymous FTP login allowed",
    23: "Telnet is insecure and sends data in plaintext",
    25: "SMTP open relay might be possible",
    110: "POP3 insecure authentication",
    143: "IMAP insecure authentication",
    3389: "RDP may be vulnerable to brute force attacks",
}

open_ports = []
lock = threading.Lock()

def scan_port(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # 1 second timeout
        result = sock.connect_ex((target_ip, port))
        sock.close()
        if result == 0:
            with lock:
                open_ports.append(port)
    except Exception as e:
        pass  # ignore errors

def scan_ports(target, start_port=1, end_port=1024):
    print(f"Starting scan on {target} from port {start_port} to {end_port}...")
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Error: Unable to resolve host {target}")
        return

    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(target_ip, port))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print(f"Scan completed on {target_ip}")
    print(f"Open ports: {open_ports}")

def generate_report(target):
    now = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"reports/scan_report_{target}_{now}.txt"
    
    with open(filename, "w") as f:
        f.write(f"Port Scan Report for {target}\n")
        f.write(f"Scan Time: {now}\n\n")
        if not open_ports:
            f.write("No open ports found in scanned range.\n")
            return

        for port in sorted(open_ports):
            service = COMMON_PORTS.get(port, "Unknown Service")
            vuln = VULN_HINTS.get(port, "No specific vulnerability info")
            f.write(f"Port {port}: {service}\n")
            f.write(f"  Potential Risk: {vuln}\n\n")

    print(f"Report saved to {filename}")

def main():
    print("=== Python Port Scanner and Vulnerability Reporter ===\n")
    target = input("Enter target IP or domain: ").strip()
    start_port = input("Enter start port (default 1): ").strip()
    end_port = input("Enter end port (default 1024): ").strip()

    start_port = int(start_port) if start_port.isdigit() else 1
    end_port = int(end_port) if end_port.isdigit() else 1024

    scan_ports(target, start_port, end_port)
    generate_report(target)

if __name__ == "__main__":
    main()
