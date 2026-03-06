#!/usr/bin/env python3
"""
WebScanner - Ferramenta de Reconhecimento e Varredura de Vulnerabilidades
Uso em Termux para profissionais de cibersegurança
AVISO: Use apenas em sites que você tem autorização para testar!
"""

import requests
import sys
import re
import json
import socket
import threading
from urllib.parse import urljoin, urlparse
from datetime import datetime

# ─── Cores para terminal ───────────────────────────────────────
R = "\033[91m"  # Vermelho
G = "\033[92m"  # Verde
Y = "\033[93m"  # Amarelo
B = "\033[94m"  # Azul
C = "\033[96m"  # Ciano
W = "\033[97m"  # Branco
RESET = "\033[0m"
BOLD = "\033[1m"

BANNER = f"""
{C}{BOLD}
╦ ╦╔═╗╔╗ ╔═╗╔═╗╔═╗╔╗╔
║║║║╣ ╠╩╗╚═╗║  ╠═╣║║║
╚╩╝╚═╝╚═╝╚═╝╚═╝╩ ╩╝╚╝
{Y}  Reconhecimento & Varredura de Vulnerabilidades
{R}  [!] USE APENAS COM AUTORIZAÇÃO DO ALVO [!]
{RESET}"""

# ─── Arquivos e pastas sensíveis ───────────────────────────────
SENSITIVE_PATHS = [
    # Arquivos de configuração
    "/.env", "/.env.local", "/.env.backup", "/.env.prod",
    "/config.php", "/config.yml", "/config.yaml", "/config.json",
    "/settings.py", "/settings.php", "/configuration.php",
    "/wp-config.php", "/wp-config.php.bak",
    # Backups
    "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db_backup.sql", "/database.sql", "/dump.sql",
    "/site.zip", "/www.zip", "/html.zip",
    # Banco de dados exposto
    "/phpmyadmin/", "/phpmyadmin", "/pma/", "/adminer.php",
    "/dbadmin/", "/sql/", "/mysql/",
    # Painéis admin
    "/admin/", "/admin", "/administrator/",
    "/wp-admin/", "/cpanel/", "/panel/",
    "/manager/", "/dashboard/", "/backend/",
    # Arquivos de log
    "/error.log", "/access.log", "/debug.log",
    "/logs/", "/log/", "/.log",
    # Git / repositórios expostos
    "/.git/", "/.git/config", "/.git/HEAD",
    "/.svn/", "/.hg/",
    # Arquivos sensíveis comuns
    "/robots.txt", "/sitemap.xml",
    "/.htaccess", "/.htpasswd",
    "/web.config", "/crossdomain.xml",
    "/server-status", "/server-info",
    # APIs e documentação
    "/api/", "/api/v1/", "/api/v2/",
    "/swagger.json", "/swagger-ui.html",
    "/openapi.json", "/api-docs/",
    # Arquivos de chave/certificado
    "/id_rsa", "/id_rsa.pub", "/.ssh/",
    "/private.key", "/server.key", "/ssl.key",
    # Outros
    "/info.php", "/phpinfo.php",
    "/test.php", "/test.html",
    "/readme.txt", "/README.md", "/CHANGELOG.md",
    "/composer.json", "/package.json",
    "/Dockerfile", "/docker-compose.yml",
    "/.dockerignore",
]

# ─── Headers a inspecionar ─────────────────────────────────────
SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-XSS-Protection",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-Powered-By",
    "Server",
    "X-AspNet-Version",
]

found_urls = []
lock = threading.Lock()


def print_banner():
    print(BANNER)


def resolve_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception:
        return "Não resolvido"


def check_url(session, base_url, path, results):
    url = urljoin(base_url, path)
    try:
        resp = session.get(url, timeout=8, allow_redirects=True, verify=False)
        code = resp.status_code
        size = len(resp.content)

        if code == 200:
            color = G
            status = "ENCONTRADO ✓"
        elif code == 403:
            color = Y
            status = "PROIBIDO (existe)"
        elif code == 401:
            color = Y
            status = "REQUER AUTH"
        elif code == 301 or code == 302:
            color = B
            status = f"REDIRECT → {resp.headers.get('Location','?')}"
        else:
            return  # ignora 404 e outros

        with lock:
            results.append({
                "url": url,
                "status": code,
                "size": size,
                "info": status
            })
            print(f"  {color}[{code}]{RESET} {url}  {color}{status}{RESET}  ({size} bytes)")

    except requests.exceptions.ConnectionError:
        pass
    except Exception:
        pass


def scan_paths(base_url, max_threads=10):
    print(f"\n{B}{BOLD}[*] Varredura de Arquivos/Diretórios Sensíveis{RESET}")
    print(f"    Testando {len(SENSITIVE_PATHS)} caminhos em {base_url}\n")

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"
    })

    results = []
    threads = []

    for path in SENSITIVE_PATHS:
        while threading.active_count() > max_threads:
            pass
        t = threading.Thread(target=check_url, args=(session, base_url, path, results))
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return results


def analyze_headers(base_url):
    print(f"\n{B}{BOLD}[*] Análise de Headers de Segurança{RESET}\n")
    findings = []
    try:
        session = requests.Session()
        resp = session.get(base_url, timeout=10, verify=False)
        headers = resp.headers

        for h in SECURITY_HEADERS:
            if h in headers:
                val = headers[h]
                if h in ["X-Powered-By", "Server", "X-AspNet-Version"]:
                    print(f"  {Y}[INFO EXPOSTA]{RESET}  {h}: {val}")
                    findings.append({"header": h, "value": val, "risk": "INFO_LEAK"})
                else:
                    print(f"  {G}[OK]{RESET}           {h}: {val}")
                    findings.append({"header": h, "value": val, "risk": "OK"})
            else:
                if h not in ["X-Powered-By", "Server", "X-AspNet-Version"]:
                    print(f"  {R}[AUSENTE]{RESET}       {h}  ← header de segurança faltando!")
                    findings.append({"header": h, "value": None, "risk": "MISSING"})

    except Exception as e:
        print(f"  {R}[ERRO]{RESET} Não foi possível conectar: {e}")

    return findings


def extract_urls_from_page(base_url):
    print(f"\n{B}{BOLD}[*] Extração de URLs / Links da Página Principal{RESET}\n")
    urls_found = set()
    try:
        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0"})
        resp = session.get(base_url, timeout=10, verify=False)
        
        # Extrai links href
        hrefs = re.findall(r'href=["\']([^"\']+)["\']', resp.text)
        srcs = re.findall(r'src=["\']([^"\']+)["\']', resp.text)
        actions = re.findall(r'action=["\']([^"\']+)["\']', resp.text)
        
        # URLs em scripts JS
        js_urls = re.findall(r'["\'](/[a-zA-Z0-9/_\-\.?=&]+)["\']', resp.text)
        api_calls = re.findall(r'fetch\(["\']([^"\']+)["\']', resp.text)
        ajax_calls = re.findall(r'url\s*:\s*["\']([^"\']+)["\']', resp.text)

        all_raw = hrefs + srcs + actions + js_urls + api_calls + ajax_calls

        parsed_base = urlparse(base_url)
        
        for u in all_raw:
            if u.startswith("http"):
                full = u
            elif u.startswith("/"):
                full = f"{parsed_base.scheme}://{parsed_base.netloc}{u}"
            else:
                full = urljoin(base_url, u)
            
            if parsed_base.netloc in full or u.startswith("/"):
                urls_found.add(full)

        for u in sorted(urls_found):
            print(f"  {C}→{RESET} {u}")

    except Exception as e:
        print(f"  {R}[ERRO]{RESET} {e}")

    return list(urls_found)


def check_open_ports(host, ports=[80, 443, 8080, 8443, 3306, 5432, 6379, 27017, 22, 21]):
    print(f"\n{B}{BOLD}[*] Varredura de Portas Comuns{RESET}\n")
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                service = {
                    80: "HTTP", 443: "HTTPS", 8080: "HTTP-ALT",
                    8443: "HTTPS-ALT", 3306: "MySQL", 5432: "PostgreSQL",
                    6379: "Redis", 27017: "MongoDB", 22: "SSH", 21: "FTP"
                }.get(port, "?")
                print(f"  {G}[ABERTA]{RESET} Porta {port} ({service})")
                open_ports.append({"port": port, "service": service})
            else:
                print(f"  {R}[FECHADA]{RESET} Porta {port}")
        except Exception:
            print(f"  {Y}[TIMEOUT]{RESET} Porta {port}")

    return open_ports


def check_robots_sitemap(base_url):
    print(f"\n{B}{BOLD}[*] Leitura de robots.txt e sitemap.xml{RESET}\n")
    extra_urls = []
    session = requests.Session()

    for path in ["/robots.txt", "/sitemap.xml"]:
        url = urljoin(base_url, path)
        try:
            resp = session.get(url, timeout=8, verify=False)
            if resp.status_code == 200:
                print(f"  {G}[{resp.status_code}]{RESET} {url}")
                lines = resp.text.splitlines()
                for line in lines:
                    if "Disallow:" in line or "Allow:" in line or "<loc>" in line:
                        line = line.strip()
                        if "<loc>" in line:
                            match = re.search(r"<loc>(.*?)</loc>", line)
                            if match:
                                u = match.group(1)
                                print(f"       {Y}→{RESET} {u}")
                                extra_urls.append(u)
                        else:
                            parts = line.split(":", 1)
                            if len(parts) == 2:
                                path_val = parts[1].strip()
                                parsed = urlparse(base_url)
                                full = f"{parsed.scheme}://{parsed.netloc}{path_val}"
                                print(f"       {Y}→{RESET} {full}")
                                extra_urls.append(full)
        except Exception as e:
            print(f"  {R}[ERRO]{RESET} {url}: {e}")

    return extra_urls


def save_report(target, ip, path_results, header_findings, page_urls, ports, extra_urls):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{urlparse(target).netloc}_{timestamp}.txt"
    
    with open(filename, "w") as f:
        f.write(f"=== RELATÓRIO DE VARREDURA ===\n")
        f.write(f"Alvo: {target}\n")
        f.write(f"IP: {ip}\n")
        f.write(f"Data: {datetime.now()}\n\n")

        f.write("=== ARQUIVOS/DIRETÓRIOS ENCONTRADOS ===\n")
        for r in path_results:
            f.write(f"[{r['status']}] {r['url']}  ({r['size']} bytes)\n")

        f.write("\n=== HEADERS ===\n")
        for h in header_findings:
            f.write(f"{h['risk']} | {h['header']}: {h['value']}\n")

        f.write("\n=== PORTAS ABERTAS ===\n")
        for p in ports:
            f.write(f"Porta {p['port']} ({p['service']})\n")

        f.write("\n=== URLs ENCONTRADAS NA PÁGINA ===\n")
        for u in page_urls:
            f.write(f"{u}\n")

        f.write("\n=== URLs DE ROBOTS/SITEMAP ===\n")
        for u in extra_urls:
            f.write(f"{u}\n")

    return filename


def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print_banner()

    # ─── Entrada do alvo ───────────────────────────────────────
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input(f"{Y}[?] Digite a URL do alvo (ex: https://example.com): {RESET}").strip()

    if not target.startswith("http"):
        target = "https://" + target

    target = target.rstrip("/")
    parsed = urlparse(target)
    host = parsed.netloc

    print(f"\n{W}{BOLD}Alvo:{RESET} {target}")
    ip = resolve_ip(host)
    print(f"{W}{BOLD}IP:{RESET}    {ip}")
    print(f"{R}{BOLD}\n[!] Certifique-se de ter autorização para escanear este alvo!{RESET}\n")
    
    confirm = input(f"{Y}[?] Confirma que tem autorização? (s/N): {RESET}").strip().lower()
    if confirm != "s":
        print(f"{R}Abortado. Execute somente em alvos autorizados.{RESET}")
        sys.exit(0)

    # ─── Executar módulos ──────────────────────────────────────
    extra_urls = check_robots_sitemap(target)
    path_results = scan_paths(target)
    header_findings = analyze_headers(target)
    page_urls = extract_urls_from_page(target)
    ports = check_open_ports(host)

    # ─── Resumo final ──────────────────────────────────────────
    print(f"\n{C}{BOLD}{'='*50}")
    print(f"  RESUMO FINAL")
    print(f"{'='*50}{RESET}")
    print(f"  {G}Arquivos/pastas encontrados:{RESET} {len([r for r in path_results if r['status'] == 200])}")
    print(f"  {Y}Proibidos (existem, mas bloqueados):{RESET} {len([r for r in path_results if r['status'] == 403])}")
    print(f"  {G}Portas abertas:{RESET} {len(ports)}")
    print(f"  {G}URLs extraídas da página:{RESET} {len(page_urls)}")
    print(f"  {Y}Headers de segurança ausentes:{RESET} {len([h for h in header_findings if h['risk'] == 'MISSING'])}")
    print(f"  {R}Headers que vazam info:{RESET} {len([h for h in header_findings if h['risk'] == 'INFO_LEAK'])}")

    # ─── Salvar relatório ──────────────────────────────────────
    save = input(f"\n{Y}[?] Salvar relatório em arquivo .txt? (s/N): {RESET}").strip().lower()
    if save == "s":
        fname = save_report(target, ip, path_results, header_findings, page_urls, ports, extra_urls)
        print(f"\n{G}[✓] Relatório salvo em: {fname}{RESET}")

    print(f"\n{C}Varredura concluída.{RESET}\n")


if __name__ == "__main__":
    main()
