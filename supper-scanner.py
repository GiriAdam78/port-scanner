import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import requests
import ssl
from urllib.parse import urlparse

# =============================
#  TOP PORT LIST (Nmap Style)
# =============================
TOP_PORTS = [
    80, 443, 22, 21, 25, 110, 143, 3306, 8080,
    53, 23, 445, 135, 139, 3389, 587, 995, 1723
]

# =============================
#  BANNER GRABBER
# =============================
def grab_banner(sock):
    try:
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        return sock.recv(1024).decode(errors="ignore").strip()
    except:
        return "Unknown Banner"

# =============================
#   PORT SCANNING FUNCTION
# =============================
def scan_port(host, port, results):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        sock.connect((host, port))

        banner = grab_banner(sock)
        results.append((port, banner))

        print(f"[OPEN] {port:<5} | Banner: {banner[:40]}")
    
    except:
        pass
    finally:
        try:
            sock.close()
        except:
            pass

# =============================
#  SAVE RESULT TO FILE
# =============================
def save_to_file(target, results):
    filename = f"scan_result_{target.replace('.', '_')}.txt"
    with open(filename, "w") as f:
        f.write(f"SCAN RESULT FOR {target}\n")
        f.write(f"Generated at: {datetime.now()}\n\n")
        for port, banner in results:
            f.write(f"Port {port}: OPEN | Banner: {banner}\n")
    print(f"\n📄 Hasil scan disimpan ke: {filename}")

# =============================
#  PORT SCANNER — RANGE MODE
# =============================
def scan_range(host, start_port, end_port):
    results = []
    print(f"\n=== SUPER FAST SCANNER ===")
    print(f"Target       : {host}")
    print(f"Port Range   : {start_port}-{end_port}")
    print(f"Threads      : 500\n")

    with ThreadPoolExecutor(max_workers=500) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, host, port, results)

    print("\nScan selesai.")
    save_to_file(host, results)

# =============================
#  PORT SCANNER — TOP PORTS
# =============================
def scan_top_ports(host):
    results = []
    print(f"\n=== TOP PORT SCANNER (NMAP STYLE) ===")
    print(f"Target       : {host}")
    print(f"Ports        : {TOP_PORTS}")
    print(f"Threads      : 200\n")

    with ThreadPoolExecutor(max_workers=200) as executor:
        for port in TOP_PORTS:
            executor.submit(scan_port, host, port, results)

    print("\nScan selesai.")
    save_to_file(host, results)

# =============================
#  HTTP STATUS CHECKER
# =============================
def check_http_status(url):
    print(f"\n=== HTTP STATUS CHECK ===")
    try:
        r = requests.get(url, timeout=5)
        print(f"[STATUS] {r.status_code} {r.reason}")
    except Exception as e:
        print(f"[ERROR] Tidak dapat mengakses URL: {e}")

# =============================
#  SSL INFORMATION CHECKER
# =============================
def check_ssl_info(url):
    parsed = urlparse(url)
    host = parsed.hostname
    port = 443

    print("\n=== SSL INFORMATION ===")

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        subject = dict(x[0] for x in cert["subject"])
        issued_to = subject.get("commonName", "Unknown")

        issuer = dict(x[0] for x in cert["issuer"])
        issued_by = issuer.get("commonName", "Unknown")

        from datetime import datetime
        valid_from = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        valid_to = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")

        print(f"Issued To     : {issued_to}")
        print(f"Issued By     : {issued_by}")
        print(f"Valid From    : {valid_from}")
        print(f"Valid Until   : {valid_to}")

        if datetime.now() > valid_to:
            print("Status        : ❌ EXPIRED")
        else:
            print("Status        : ✅ VALID")

    except Exception as e:
        print(f"[SSL ERROR] Tidak bisa mengambil SSL info: {e}")

# =============================
#  WEB SCANNER MODE
# =============================
def web_scan(url):
    print(f"\n=== WEB SCAN MODE ===")
    print(f"Target: {url}\n")

    check_http_status(url)

    if url.startswith("https://"):
        check_ssl_info(url)
    else:
        print("\nSSL: Tidak tersedia karena memakai HTTP.")

# =============================
#  MAIN PROGRAM
# =============================
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Cara pakai:")
        print("  python super_scanner.py <host/url> <mode> [start] [end]")
        print("\nMode:")
        print("  top        → scan top ports (nmap style)")
        print("  full       → scan port 1–65535")
        print("  range      → scan port sesuai range")
        print("  web        → cek status HTTP & SSL")
        print("\nContoh:")
        print("  python super_scanner.py google.com top")
        print("  python super_scanner.py example.com full")
        print("  python super_scanner.py test.com range 1 1000")
        print("  python super_scanner.py https://example.com web")
        sys.exit(1)

    target = sys.argv[1]
    mode = sys.argv[2]

    if mode == "top":
        scan_top_ports(target)

    elif mode == "full":
        scan_range(target, 1, 65535)

    elif mode == "range":
        if len(sys.argv) != 5:
            print("Usage: python super_scanner.py <host> range <start> <end>")
            sys.exit(1)
        start = int(sys.argv[3])
        end = int(sys.argv[4])
        scan_range(target, start, end)

    elif mode == "web":
        web_scan(target)

    else:
        print("Mode tidak dikenal.")
